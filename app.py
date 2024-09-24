import os
import boto3
import pyotp
import pymongo
import smtplib
import qrcode
import io
import uuid
import random
import string
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from flask import Flask, request, jsonify, render_template, redirect, session, url_for, flash, make_response, send_from_directory
from pymongo import MongoClient, errors
from botocore.exceptions import NoCredentialsError, PartialCredentialsError, ClientError

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Change this to a more secure key for production

# Connect to MongoDB
mongo_client = MongoClient("mongodb://localhost:27017/")
db = mongo_client['CAF']
users_collection = db["users"]

def get_user_credentials(username):
    user = users_collection.find_one({"username": username})
    if user:
        return user.get('access_key_id'), user.get('secret_access_key'), user.get('region')
    return None, None, None

def save_user(user):
    users_collection.update_one(
        {'username': user['username']},
        {'$set': user},
        upsert=True
    )
    print(f"User {user['username']} saved to MongoDB.")

def generate_otp_secret():
    return pyotp.random_base32()

def send_otp_via_email(email, otp):
    sender_email = "shubhamkale9112@gmail.com"
    sender_password = "hyeo rrug xasl oxis"  # Use environment variables or a secure method to handle this
    receiver_email = email

    subject = "Your OTP Code"
    body = f"Your OTP code is: {otp}"

    msg = MIMEMultipart()
    msg['From'] = sender_email
    msg['To'] = receiver_email
    msg['Subject'] = subject

    msg.attach(MIMEText(body, 'plain'))

    try:
        server = smtplib.SMTP_SSL('smtp.gmail.com', 465)
        server.login(sender_email, sender_password)
        server.sendmail(sender_email, receiver_email, msg.as_string())
        server.close()
        print("Email sent successfully")
    except Exception as e:
        print(f"Failed to send email: {e}")

@app.route('/index')
def index():
    return render_template('index.html')

@app.route('/signup', methods=['POST'])
def signup():
    username = request.form['username']
    password = request.form['password']
    email = request.form['email']

    user = users_collection.find_one({"username": username})
    if user:
        flash('Username already exists!', 'error')
        return redirect(url_for('index'))

    otp_secret = generate_otp_secret()
    user = {'username': username, 'password': password, 'email': email, 'otp_secret': otp_secret}
    save_user(user)

    flash('Sign up successful! Please sign in.', 'success')
    return redirect(url_for('index'))

@app.route('/signin', methods=['POST'])
def signin():
    username = request.form['username']
    password = request.form['password']

    user = users_collection.find_one({"username": username})
    if not user or user['password'] != password:
        flash('Invalid credentials', 'error')
        return redirect(url_for('index'))

    session['username'] = username
    return redirect(url_for('two_factor_auth'))

@app.route('/two_factor_auth', methods=['GET', 'POST'])
def two_factor_auth():
    if 'username' not in session:
        return redirect(url_for('index'))

    username = session['username']
    otp_secret = users_collection.find_one({"username": username})['otp_secret']
    totp = pyotp.TOTP(otp_secret)

    if request.method == 'POST':
        otp = request.form['otp']
        if totp.verify(otp):
            session['authenticated'] = True
            return redirect(url_for('CloudSelect'))
        else:
            flash('Invalid OTP', 'error')
            return redirect(url_for('two_factor_auth'))

    return render_template('two_factor_auth.html', username=username, otp_secret=otp_secret)

@app.route('/qr_code')
def qr_code():
    if 'username' not in session:
        return redirect(url_for('index'))

    username = session['username']
    otp_secret = users_collection.find_one({"username": username})['otp_secret']
    totp = pyotp.TOTP(otp_secret)
    uri = totp.provisioning_uri(name=username, issuer_name='FlaskAuthApp')

    img = qrcode.make(uri)
    buf = io.BytesIO()
    img.save(buf)
    buf.seek(0)

    response = make_response(buf.read())
    response.headers['Content-Type'] = 'image/png'
    return response

@app.route('/clouds')
def clouds():
    if 'authenticated' not in session:
        return redirect(url_for('index'))

    username = session['username']
    user_info = users_collection.find_one({"username": username})

    return render_template('clouds.html', username=username, user_info=user_info)

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        user = users_collection.find_one({"email": email})
        if user:
            otp = ''.join(random.choices(string.digits, k=6))
            session['reset_otp'] = otp
            session['reset_username'] = user['username']
            send_otp_via_email(email, otp)
            flash('OTP sent to your email', 'info')
            return redirect(url_for('reset_password'))
        flash('Email not found', 'error')

    return render_template('forgot_password.html')

@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    if request.method == 'POST':
        otp = request.form['otp']
        new_password = request.form['new_password']

        if otp == session.get('reset_otp'):
            username = session.get('reset_username')
            users_collection.update_one({'username': username}, {'$set': {'password': new_password}})
            flash('Password reset successful', 'success')
            return redirect(url_for('index'))
        else:
            flash('Invalid OTP', 'error')

    return render_template('reset_password.html')

@app.route('/check_mongodb')
def check_mongodb():
    try:
        mongo_client.admin.command('ping')
        return jsonify(status='success', message='MongoDB is connected')
    except errors.ConnectionError:
        return jsonify(status='error', message='Failed to connect to MongoDB')

@app.route('/save-aws-credentials', methods=['POST'])
def save_aws_credentials():
    if 'username' not in session:
        return jsonify({'message': 'Unauthorized'}), 401

    username = session['username']
    access_key_id = request.form['access_key_id']
    secret_access_key = request.form['secret_access_key']
    region = request.form['region']

    # Update the user's AWS credentials directly in the document
    users_collection.update_one(
        {'username': username},
        {'$set': {
            'access_key_id': access_key_id,
            'secret_access_key': secret_access_key,
            'region': region
        }},
        upsert=True
    )

    return jsonify({'message': 'Credentials saved successfully', 'redirect': url_for('clouds')})

@app.route('/home')
def home():
    authenticated = request.cookies.get('authenticated')
    if authenticated != 'true':
        return redirect(url_for('login'))
    return "Home page"

@app.route('/signout')
def logout():
    response = make_response(redirect(url_for('login')))
    response.set_cookie('authenticated', '', expires=0)
    return response

@app.route('/CloudSelect')
def CloudSelect():
    return render_template('CloudSelect.html')

@app.route('/')
def land():
    return render_template('land.html')

@app.route('/login')
def login():
    return render_template('login.html')

@app.route('/services')
def services():
    return render_template('services.html')

@app.route('/launchec2')
def ec2():
    return render_template('ec2.html')

@app.route('/<path:path>')
def serve_ec2_static_files(path):
    return send_from_directory('static', path)

@app.route('/launch_instance', methods=['POST'])
def launch_instance():
    ami_id = request.args.get('ami_id')
    instance_type = request.args.get('instance_type')
    count = request.args.get('count')

    # Fetch AWS credentials from MongoDB
    username = session.get('username')
    if not username:
        return jsonify({'message': 'Unauthorized'}), 401

    access_key_id, secret_access_key, region = get_user_credentials(username)
    if not all([access_key_id, secret_access_key, region]):
        return jsonify({'message': 'AWS credentials not found'}), 404

    try:
        ec2 = boto3.client(
            'ec2',
            aws_access_key_id=access_key_id,
            aws_secret_access_key=secret_access_key,
            region_name=region
        )
        instances = ec2.run_instances(
            ImageId=ami_id,
            InstanceType=instance_type,
            MinCount=int(count),
            MaxCount=int(count)
        )

        instance_ids = [instance['InstanceId'] for instance in instances['Instances']]
        return jsonify({'message': 'Instances launched successfully', 'instance_ids': instance_ids})
    except (NoCredentialsError, PartialCredentialsError) as e:
        return jsonify({'message': 'AWS credentials error', 'error': str(e)}), 400
    except ClientError as e:
        return jsonify({'message': 'Failed to launch instances', 'error': str(e)}), 500
    

@app.route('/create_vpc', methods=['POST'])
def create_vpc():
    cidr_block = request.form['cidr_block']

    # Fetch AWS credentials from MongoDB
    username = session.get('username')
    if not username:
        return jsonify({'message': 'Unauthorized'}), 401

    access_key_id, secret_access_key, region = get_user_credentials(username)
    if not all([access_key_id, secret_access_key, region]):
        return jsonify({'message': 'AWS credentials not found'}), 404

    try:
        ec2 = boto3.client(
            'ec2',
            aws_access_key_id=access_key_id,
            aws_secret_access_key=secret_access_key,
            region_name=region
        )
        
        # Create VPC
        vpc_response = ec2.create_vpc(
            CidrBlock=cidr_block,
            AmazonProvidedIpv6CidrBlock=False
        )
        vpc_id = vpc_response['Vpc']['VpcId']

        return jsonify({'message': f'VPC with ID {vpc_id} created successfully.'}), 200
    except (NoCredentialsError, PartialCredentialsError) as e:
        return jsonify({'message': 'AWS credentials error', 'error': str(e)}), 400
    except ClientError as e:
        return jsonify({'message': 'Failed to create VPC', 'error': str(e)}), 500
    except Exception as e:
        app.logger.error(f"Error creating VPC: {str(e)}")
        return jsonify({'error': str(e)}), 500

# Route to render VPC creation page
@app.route('/vpc')
def vpc():
    return render_template('vpc.html')

# Route to serve static files
@app.route('/static/<path:path>')
def serve_static_files(path):
    return send_from_directory('static', path)

@app.route('/create_bucket', methods=['POST'])
def create_bucket():
    # Fetch AWS credentials from MongoDB
    username = session.get('username')
    if not username:
        return jsonify({'message': 'Unauthorized'}), 401

    access_key_id, secret_access_key, region = get_user_credentials(username)
    if not all([access_key_id, secret_access_key, region]):
        return jsonify({'message': 'AWS credentials not found'}), 404

    try:
        # Generate a unique bucket name
        bucket_name = f"bucket-{uuid.uuid4()}"

        s3 = boto3.client(
            's3',
            aws_access_key_id=access_key_id,
            aws_secret_access_key=secret_access_key,
            region_name=region
        )
        s3.create_bucket(Bucket=bucket_name, CreateBucketConfiguration={'LocationConstraint': region})

        return jsonify({"message": "Bucket created successfully", "bucket_name": bucket_name}), 201
    except (NoCredentialsError, PartialCredentialsError) as e:
        return jsonify({'message': 'AWS credentials error', 'error': str(e)}), 400
    except ClientError as e:
        return jsonify({'message': 'Failed to create bucket', 'error': str(e)}), 500
    except Exception as e:
        app.logger.error(f"Error creating bucket: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/delete_bucket/<bucket_name>', methods=['DELETE'])
def delete_bucket(bucket_name):
    # Fetch AWS credentials from MongoDB
    username = session.get('username')
    if not username:
        return jsonify({'message': 'Unauthorized'}), 401

    access_key_id, secret_access_key, region = get_user_credentials(username)
    if not all([access_key_id, secret_access_key, region]):
        return jsonify({'message': 'AWS credentials not found'}), 404

    try:
        s3 = boto3.client(
            's3',
            aws_access_key_id=access_key_id,
            aws_secret_access_key=secret_access_key,
            region_name=region
        )
        s3.delete_bucket(Bucket=bucket_name)

        return jsonify({"message": "Bucket deleted successfully"}), 200
    except (NoCredentialsError, PartialCredentialsError) as e:
        return jsonify({'message': 'AWS credentials error', 'error': str(e)}), 400
    except ClientError as e:
        return jsonify({'message': 'Failed to delete bucket', 'error': str(e)}), 500
    except Exception as e:
        app.logger.error(f"Error deleting bucket: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/upload_file/<bucket_name>', methods=['POST'])
def upload_file(bucket_name):
    # Fetch AWS credentials from MongoDB
    username = session.get('username')
    if not username:
        return jsonify({'message': 'Unauthorized'}), 401

    access_key_id, secret_access_key, region = get_user_credentials(username)
    if not all([access_key_id, secret_access_key, region]):
        return jsonify({'message': 'AWS credentials not found'}), 404

    if 'file' not in request.files:
        return jsonify({"error": "No file part in the request"}), 400
    file = request.files['file']
    if file.filename == '':
        return jsonify({"error": "No selected file"}), 400

    try:
        s3 = boto3.client(
            's3',
            aws_access_key_id=access_key_id,
            aws_secret_access_key=secret_access_key,
            region_name=region
        )
        s3.upload_fileobj(file, bucket_name, file.filename)

        return jsonify({"message": "File uploaded successfully"}), 200
    except (NoCredentialsError, PartialCredentialsError) as e:
        return jsonify({'message': 'AWS credentials error', 'error': str(e)}), 400
    except ClientError as e:
        return jsonify({'message': 'Failed to upload file', 'error': str(e)}), 500
    except Exception as e:
        app.logger.error(f"Error uploading file: {str(e)}")
        return jsonify({'error': str(e)}), 500

# Route to render S3 page
@app.route('/s3')
def s3():
    return render_template('s3.html')

# Route to serve static files
@app.route('/static/<path:path>')
def serve_s3_static_files(path):
    return send_from_directory('static', path)


#### ##### SQS code

@app.route('/create_sqs', methods=['POST'])
def create_sqs():
    username = session.get('username')
    if not username:
        return jsonify({'message': 'Unauthorized'}), 401

    access_key_id, secret_access_key, region = get_user_credentials(username)
    if not all([access_key_id, secret_access_key, region]):
        return jsonify({'message': 'AWS credentials not found'}), 404

    data = request.json
    queue_name = data.get('queue_name')
    delay_seconds = data.get('delay_seconds')
    maximum_message_size = data.get('maximum_message_size')
    message_retention_period = data.get('message_retention_period')
    environment_tag = data.get('environment_tag')
    owner_tag = data.get('owner_tag')

    if not queue_name:
        return jsonify({"error": "queue_name is required"}), 400

    try:
        sqs = boto3.client(
            'sqs',
            aws_access_key_id=access_key_id,
            aws_secret_access_key=secret_access_key,
            region_name=region
        )

        attributes = {}
        if delay_seconds is not None:
            if not (0 <= int(delay_seconds) <= 900):
                return jsonify({"error": "Invalid value for delay_seconds. Must be between 0 and 900."}), 400
            attributes['DelaySeconds'] = str(delay_seconds)
        if maximum_message_size is not None:
            if not (1024 <= int(maximum_message_size) <= 262144):
                return jsonify({"error": "Invalid value for maximum_message_size. Must be between 1024 and 262144."}), 400
            attributes['MaximumMessageSize'] = str(maximum_message_size)
        if message_retention_period is not None:
            if not (60 <= int(message_retention_period) <= 1209600):
                return jsonify({"error": "Invalid value for message_retention_period. Must be between 60 and 1209600."}), 400
            attributes['MessageRetentionPeriod'] = str(message_retention_period)

        tags = {}
        if environment_tag:
            tags['Environment'] = environment_tag
        if owner_tag:
            tags['Owner'] = owner_tag

        try:
            response = sqs.get_queue_url(QueueName=queue_name)
            queue_url = response['QueueUrl']
            return jsonify({"message": "Queue already exists", "queue_url": queue_url}), 200
        except ClientError as e:
            if e.response['Error']['Code'] == 'AWS.SimpleQueueService.NonExistentQueue':
                pass
            else:
                return jsonify({"error": str(e)}), 500

        response = sqs.create_queue(
            QueueName=queue_name,
            Attributes=attributes,
            tags=tags
        )
        return jsonify({"message": "Queue created successfully", "queue_url": response['QueueUrl']}), 201
    except (NoCredentialsError, PartialCredentialsError) as e:
        return jsonify({'message': 'AWS credentials error', 'error': str(e)}), 400
    except ClientError as e:
        return jsonify({'message': 'Failed to create queue', 'error': str(e)}), 500
    except Exception as e:
        app.logger.error(f"Error creating queue: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/sqs')
def sqs():
    return render_template('sqs.html')

@app.route('/static/<path:path>')
def serve_sqs_static_files(path):
    return send_from_directory('static', path)

#### end of SQS code ####


##### code SNS

@app.route('/sns')
def sns():
    return render_template('sns.html')

@app.route('/create_topic', methods=['POST'])
def create_topic():
    username = session.get('username')
    if not username:
        return jsonify({'message': 'Unauthorized'}), 401

    access_key_id, secret_access_key, region = get_user_credentials(username)
    if not all([access_key_id, secret_access_key, region]):
        return jsonify({'message': 'AWS credentials not found'}), 404

    topic_name = request.json.get('topic_name')
    if not topic_name:
        return jsonify({'error': 'Topic name is required'}), 400

    try:
        sns_client = boto3.client(
            'sns',
            aws_access_key_id=access_key_id,
            aws_secret_access_key=secret_access_key,
            region_name=region
        )
        response = sns_client.create_topic(Name=topic_name)
        return jsonify(response), 200
    except (NoCredentialsError, PartialCredentialsError) as e:
        return jsonify({'message': 'AWS credentials error', 'error': str(e)}), 400
    except ClientError as e:
        return jsonify({'message': 'Failed to create topic', 'error': str(e)}), 500

@app.route('/list_topics', methods=['GET'])
def list_topics():
    username = session.get('username')
    if not username:
        return jsonify({'message': 'Unauthorized'}), 401

    access_key_id, secret_access_key, region = get_user_credentials(username)
    if not all([access_key_id, secret_access_key, region]):
        return jsonify({'message': 'AWS credentials not found'}), 404

    try:
        sns_client = boto3.client(
            'sns',
            aws_access_key_id=access_key_id,
            aws_secret_access_key=secret_access_key,
            region_name=region
        )
        response = sns_client.list_topics()
        return jsonify(response), 200
    except (NoCredentialsError, PartialCredentialsError) as e:
        return jsonify({'message': 'AWS credentials error', 'error': str(e)}), 400
    except ClientError as e:
        return jsonify({'message': 'Failed to list topics', 'error': str(e)}), 500

@app.route('/publish_message', methods=['POST'])
def publish_message():
    username = session.get('username')
    if not username:
        return jsonify({'message': 'Unauthorized'}), 401

    access_key_id, secret_access_key, region = get_user_credentials(username)
    if not all([access_key_id, secret_access_key, region]):
        return jsonify({'message': 'AWS credentials not found'}), 404

    topic_arn = request.json.get('topic_arn')
    message = request.json.get('message')
    if not topic_arn or not message:
        return jsonify({'error': 'Topic ARN and message are required'}), 400

    try:
        sns_client = boto3.client(
            'sns',
            aws_access_key_id=access_key_id,
            aws_secret_access_key=secret_access_key,
            region_name=region
        )
        response = sns_client.publish(TopicArn=topic_arn, Message=message)
        return jsonify(response), 200
    except (NoCredentialsError, PartialCredentialsError) as e:
        return jsonify({'message': 'AWS credentials error', 'error': str(e)}), 400
    except ClientError as e:
        return jsonify({'message': 'Failed to publish message', 'error': str(e)}), 500

@app.route('/delete_topic', methods=['DELETE'])
def delete_topic():
    username = session.get('username')
    if not username:
        return jsonify({'message': 'Unauthorized'}), 401

    access_key_id, secret_access_key, region = get_user_credentials(username)
    if not all([access_key_id, secret_access_key, region]):
        return jsonify({'message': 'AWS credentials not found'}), 404

    topic_arn = request.json.get('topic_arn')
    if not topic_arn:
        return jsonify({'error': 'Topic ARN is required'}), 400

    try:
        sns_client = boto3.client(
            'sns',
            aws_access_key_id=access_key_id,
            aws_secret_access_key=secret_access_key,
            region_name=region
        )
        response = sns_client.delete_topic(TopicArn=topic_arn)
        return jsonify(response), 200
    except (NoCredentialsError, PartialCredentialsError) as e:
        return jsonify({'message': 'AWS credentials error', 'error': str(e)}), 400
    except ClientError as e:
        return jsonify({'message': 'Failed to delete topic', 'error': str(e)}), 500


##### dynamoDB code

@app.route('/dynamodb')
def dynamodb():
    return render_template('dynamodb.html')

@app.route('/create_table', methods=['POST'])
def create_table():
    username = session.get('username')
    if not username:
        return jsonify({'message': 'Unauthorized'}), 401

    access_key_id, secret_access_key, region = get_user_credentials(username)
    if not all([access_key_id, secret_access_key, region]):
        return jsonify({'message': 'AWS credentials not found'}), 404

    data = request.get_json()
    table_name = data.get('table_name')
    key_schema = data.get('key_schema')
    attribute_definitions = data.get('attribute_definitions')
    provisioned_throughput = data.get('provisioned_throughput')

    try:
        dynamodb = boto3.resource(
            'dynamodb',
            aws_access_key_id=access_key_id,
            aws_secret_access_key=secret_access_key,
            region_name=region
        )
        table = dynamodb.create_table(
            TableName=table_name,
            KeySchema=key_schema,
            AttributeDefinitions=attribute_definitions,
            ProvisionedThroughput=provisioned_throughput
        )
        table.wait_until_exists()
        return jsonify({'message': f'Table {table_name} created successfully!'}), 201
    except (NoCredentialsError, PartialCredentialsError) as e:
        return jsonify({'message': 'AWS credentials error', 'error': str(e)}), 400
    except ClientError as e:
        return jsonify({'message': 'Failed to create table', 'error': str(e)}), 500

@app.route('/insert_item', methods=['POST'])
def insert_item():
    username = session.get('username')
    if not username:
        return jsonify({'message': 'Unauthorized'}), 401

    access_key_id, secret_access_key, region = get_user_credentials(username)
    if not all([access_key_id, secret_access_key, region]):
        return jsonify({'message': 'AWS credentials not found'}), 404

    data = request.get_json()
    table_name = data.get('table_name')
    item = data.get('item')

    try:
        dynamodb = boto3.resource(
            'dynamodb',
            aws_access_key_id=access_key_id,
            aws_secret_access_key=secret_access_key,
            region_name=region
        )
        table = dynamodb.Table(table_name)
        table.put_item(Item=item)
        return jsonify({'message': 'Item inserted successfully!'}), 201
    except ClientError as e:
        return jsonify({'message': 'Failed to insert item', 'error': str(e)}), 500

@app.route('/get_item', methods=['GET'])
def get_item():
    username = session.get('username')
    if not username:
        return jsonify({'message': 'Unauthorized'}), 401

    access_key_id, secret_access_key, region = get_user_credentials(username)
    if not all([access_key_id, secret_access_key, region]):
        return jsonify({'message': 'AWS credentials not found'}), 404

    table_name = request.args.get('table_name')
    key = request.args.get('key')

    try:
        dynamodb = boto3.resource(
            'dynamodb',
            aws_access_key_id=access_key_id,
            aws_secret_access_key=secret_access_key,
            region_name=region
        )
        table = dynamodb.Table(table_name)
        response = table.get_item(Key=key)
        if 'Item' in response:
            return jsonify(response['Item']), 200
        else:
            return jsonify({'error': 'Item not found'}), 404
    except ClientError as e:
        return jsonify({'message': 'Failed to get item', 'error': str(e)}), 500

@app.route('/delete_item', methods=['DELETE'])
def delete_item():
    username = session.get('username')
    if not username:
        return jsonify({'message': 'Unauthorized'}), 401

    access_key_id, secret_access_key, region = get_user_credentials(username)
    if not all([access_key_id, secret_access_key, region]):
        return jsonify({'message': 'AWS credentials not found'}), 404

    data = request.get_json()
    table_name = data.get('table_name')
    key = data.get('key')

    try:
        dynamodb = boto3.resource(
            'dynamodb',
            aws_access_key_id=access_key_id,
            aws_secret_access_key=secret_access_key,
            region_name=region
        )
        table = dynamodb.Table(table_name)
        table.delete_item(Key=key)
        return jsonify({'message': 'Item deleted successfully!'}), 200
    except ClientError as e:
        return jsonify({'message': 'Failed to delete item', 'error': str(e)}), 500

@app.route('/delete_table', methods=['DELETE'])
def delete_table():
    username = session.get('username')
    if not username:
        return jsonify({'message': 'Unauthorized'}), 401

    access_key_id, secret_access_key, region = get_user_credentials(username)
    if not all([access_key_id, secret_access_key, region]):
        return jsonify({'message': 'AWS credentials not found'}), 404

    table_name = request.get_json().get('table_name')

    try:
        dynamodb = boto3.resource(
            'dynamodb',
            aws_access_key_id=access_key_id,
            aws_secret_access_key=secret_access_key,
            region_name=region
        )
        table = dynamodb.Table(table_name)
        table.delete()
        return jsonify({'message': f'Table {table_name} deleted successfully!'}), 200
    except ClientError as e:
        return jsonify({'message': 'Failed to delete table', 'error': str(e)}), 500

#### LB code

@app.route('/lb')
def lb():
    return render_template('lb.html')

@app.route('/create-load-balancer', methods=['POST'])
def create_load_balancer():
    username = session.get('username')
    if not username:
        return jsonify({'message': 'Unauthorized'}), 401

    access_key_id, secret_access_key, region = get_user_credentials(username)
    if not all([access_key_id, secret_access_key, region]):
        return jsonify({'message': 'AWS credentials not found'}), 404

    data = request.get_json()
    name = data.get('name')
    subnets = data.get('subnets')
    security_groups = data.get('security_groups', [])
    scheme = data.get('scheme', 'internet-facing')
    tags = data.get('tags', [])

    try:
        elb_client = boto3.client(
            'elbv2',
            aws_access_key_id=access_key_id,
            aws_secret_access_key=secret_access_key,
            region_name=region
        )
        response = elb_client.create_load_balancer(
            Name=name,
            Subnets=subnets,
            SecurityGroups=security_groups,
            Scheme=scheme,
            Tags=tags
        )
        return jsonify({'message': 'Load balancer created successfully', 'load_balancer': response}), 201
    except (NoCredentialsError, PartialCredentialsError) as e:
        return jsonify({'message': 'AWS credentials error', 'error': str(e)}), 400
    except ClientError as e:
        return jsonify({'message': 'Failed to create load balancer', 'error': str(e)}), 500

@app.route('/describe-load-balancers', methods=['GET'])
def describe_load_balancers():
    username = session.get('username')
    if not username:
        return jsonify({'message': 'Unauthorized'}), 401

    access_key_id, secret_access_key, region = get_user_credentials(username)
    if not all([access_key_id, secret_access_key, region]):
        return jsonify({'message': 'AWS credentials not found'}), 404

    try:
        elb_client = boto3.client(
            'elbv2',
            aws_access_key_id=access_key_id,
            aws_secret_access_key=secret_access_key,
            region_name=region
        )
        response = elb_client.describe_load_balancers()
        return jsonify({'message': 'Load balancers described successfully', 'load_balancers': response}), 200
    except (NoCredentialsError, PartialCredentialsError) as e:
        return jsonify({'message': 'AWS credentials error', 'error': str(e)}), 400
    except ClientError as e:
        return jsonify({'message': 'Failed to describe load balancers', 'error': str(e)}), 500

@app.route('/delete-load-balancer', methods=['DELETE'])
def delete_load_balancer():
    username = session.get('username')
    if not username:
        return jsonify({'message': 'Unauthorized'}), 401

    access_key_id, secret_access_key, region = get_user_credentials(username)
    if not all([access_key_id, secret_access_key, region]):
        return jsonify({'message': 'AWS credentials not found'}), 404

    data = request.get_json()
    load_balancer_arn = data.get('load_balancer_arn')

    try:
        elb_client = boto3.client(
            'elbv2',
            aws_access_key_id=access_key_id,
            aws_secret_access_key=secret_access_key,
            region_name=region
        )
        response = elb_client.delete_load_balancer(
            LoadBalancerArn=load_balancer_arn
        )
        return jsonify({'message': 'Load balancer deleted successfully', 'response': response}), 200
    except (NoCredentialsError, PartialCredentialsError) as e:
        return jsonify({'message': 'AWS credentials error', 'error': str(e)}), 400
    except ClientError as e:
        return jsonify({'message': 'Failed to delete load balancer', 'error': str(e)}), 500


#### SES code
@app.route('/ses')
def ses():
    return render_template('ses.html')

@app.route('/send-email', methods=['POST'])
def send_email():
    data = request.get_json()
    source = data.get('source')
    to_addresses = data.get('to_addresses')
    subject = data.get('subject')
    body = data.get('body')

    # Fetch AWS credentials from MongoDB
    username = session.get('username')
    if not username:
        return jsonify({'message': 'Unauthorized'}), 401

    access_key_id, secret_access_key, region = get_user_credentials(username)
    if not all([access_key_id, secret_access_key, region]):
        return jsonify({'message': 'AWS credentials not found'}), 404

    try:
        ses_client = boto3.client(
            'ses',
            aws_access_key_id=access_key_id,
            aws_secret_access_key=secret_access_key,
            region_name=region
        )
        response = ses_client.send_email(
            Source=source,
            Destination={'ToAddresses': to_addresses},
            Message={
                'Subject': {'Data': subject},
                'Body': {'Text': {'Data': body}}
            }
        )
        return jsonify({'message': 'Email sent successfully', 'response': response}), 200
    except (NoCredentialsError, PartialCredentialsError) as e:
        return jsonify({'message': 'AWS credentials error', 'error': str(e)}), 400
    except ClientError as e:
        return jsonify({'message': 'Failed to send email', 'error': str(e)}), 500

@app.route('/list-verified-emails', methods=['GET'])
def list_verified_emails():
    # Fetch AWS credentials from MongoDB
    username = session.get('username')
    if not username:
        return jsonify({'message': 'Unauthorized'}), 401

    access_key_id, secret_access_key, region = get_user_credentials(username)
    if not all([access_key_id, secret_access_key, region]):
        return jsonify({'message': 'AWS credentials not found'}), 404

    try:
        ses_client = boto3.client(
            'ses',
            aws_access_key_id=access_key_id,
            aws_secret_access_key=secret_access_key,
            region_name=region
        )
        response = ses_client.list_verified_email_addresses()
        return jsonify(response['VerifiedEmailAddresses']), 200
    except (NoCredentialsError, PartialCredentialsError) as e:
        return jsonify({'message': 'AWS credentials error', 'error': str(e)}), 400
    except ClientError as e:
        return jsonify({'message': 'Failed to list verified emails', 'error': str(e)}), 500

@app.route('/verify-email', methods=['POST'])
def verify_email():
    data = request.get_json()
    email_address = data.get('email_address')

    # Fetch AWS credentials from MongoDB
    username = session.get('username')
    if not username:
        return jsonify({'message': 'Unauthorized'}), 401

    access_key_id, secret_access_key, region = get_user_credentials(username)
    if not all([access_key_id, secret_access_key, region]):
        return jsonify({'message': 'AWS credentials not found'}), 404

    try:
        ses_client = boto3.client(
            'ses',
            aws_access_key_id=access_key_id,
            aws_secret_access_key=secret_access_key,
            region_name=region
        )
        response = ses_client.verify_email_identity(
            EmailAddress=email_address
        )
        return jsonify({'message': 'Verification email sent', 'response': response}), 200
    except (NoCredentialsError, PartialCredentialsError) as e:
        return jsonify({'message': 'AWS credentials error', 'error': str(e)}), 400
    except ClientError as e:
        return jsonify({'message': 'Failed to verify email', 'error': str(e)}), 500
    

##### code build code

@app.route('/codebuild')
def codebuild():
    return render_template('codebuild.html')

@app.route('/create_project', methods=['POST'])
def create_project():
    data = request.json

    # Fetch AWS credentials from MongoDB
    username = session.get('username')
    if not username:
        return jsonify({'message': 'Unauthorized'}), 401

    access_key_id, secret_access_key, region = get_user_credentials(username)
    if not all([access_key_id, secret_access_key, region]):
        return jsonify({'message': 'AWS credentials not found'}), 404

    try:
        codebuild_client = boto3.client(
            'codebuild',
            aws_access_key_id=access_key_id,
            aws_secret_access_key=secret_access_key,
            region_name=region
        )
        response = codebuild_client.create_project(
            name=data['name'],
            source={
                'type': data['source']['type'],
                'location': data['source']['location']
            },
            artifacts={
                'type': 'NO_ARTIFACTS'
            },
            environment={
                'type': 'LINUX_CONTAINER',
                'image': 'aws/codebuild/standard:4.0',
                'computeType': 'BUILD_GENERAL1_SMALL'
            },
            serviceRole=data['serviceRole']
        )
        return jsonify({'message': 'Project created successfully', 'response': response}), 201
    except (NoCredentialsError, PartialCredentialsError) as e:
        return jsonify({'message': 'AWS credentials error', 'error': str(e)}), 400
    except ClientError as e:
        return jsonify({'message': 'Failed to create project', 'error': str(e)}), 500

@app.route('/delete_project', methods=['DELETE'])
def delete_project():
    data = request.json

    # Fetch AWS credentials from MongoDB
    username = session.get('username')
    if not username:
        return jsonify({'message': 'Unauthorized'}), 401

    access_key_id, secret_access_key, region = get_user_credentials(username)
    if not all([access_key_id, secret_access_key, region]):
        return jsonify({'message': 'AWS credentials not found'}), 404

    try:
        codebuild_client = boto3.client(
            'codebuild',
            aws_access_key_id=access_key_id,
            aws_secret_access_key=secret_access_key,
            region_name=region
        )
        response = codebuild_client.delete_project(name=data['name'])
        return jsonify({'message': 'Project deleted successfully', 'response': response}), 200
    except (NoCredentialsError, PartialCredentialsError) as e:
        return jsonify({'message': 'AWS credentials error', 'error': str(e)}), 400
    except ClientError as e:
        return jsonify({'message': 'Failed to delete project', 'error': str(e)}), 500

@app.route('/list_projects', methods=['GET'])
def list_projects():
    # Fetch AWS credentials from MongoDB
    username = session.get('username')
    if not username:
        return jsonify({'message': 'Unauthorized'}), 401

    access_key_id, secret_access_key, region = get_user_credentials(username)
    if not all([access_key_id, secret_access_key, region]):
        return jsonify({'message': 'AWS credentials not found'}), 404

    try:
        codebuild_client = boto3.client(
            'codebuild',
            aws_access_key_id=access_key_id,
            aws_secret_access_key=secret_access_key,
            region_name=region
        )
        response = codebuild_client.list_projects()
        return jsonify({'message': 'Projects listed successfully', 'response': response}), 200
    except (NoCredentialsError, PartialCredentialsError) as e:
        return jsonify({'message': 'AWS credentials error', 'error': str(e)}), 400
    except ClientError as e:
        return jsonify({'message': 'Failed to list projects', 'error': str(e)}), 500

##### code deploy

@app.route('/codedeploy')
def codedeploy():
    return render_template('codedeploy.html')

@app.route('/codedeploy/create-application', methods=['POST'])
def create_application():
    data = request.get_json()
    application_name = data.get('application_name')

    # Fetch AWS credentials from MongoDB
    username = session.get('username')
    if not username:
        return jsonify({'message': 'Unauthorized'}), 401

    access_key_id, secret_access_key, region = get_user_credentials(username)
    if not all([access_key_id, secret_access_key, region]):
        return jsonify({'message': 'AWS credentials not found'}), 404

    try:
        codedeploy_client = boto3.client(
            'codedeploy',
            aws_access_key_id=access_key_id,
            aws_secret_access_key=secret_access_key,
            region_name=region
        )
        response = codedeploy_client.create_application(
            applicationName=application_name
        )
        return jsonify({'message': 'Application created successfully', 'response': response}), 201
    except (NoCredentialsError, PartialCredentialsError) as e:
        return jsonify({'message': 'AWS credentials error', 'error': str(e)}), 400
    except ClientError as e:
        return jsonify({'message': 'Failed to create application', 'error': str(e)}), 500

@app.route('/codedeploy/delete-application', methods=['DELETE'])
def delete_application():
    data = request.get_json()
    application_name = data.get('application_name')

    # Fetch AWS credentials from MongoDB
    username = session.get('username')
    if not username:
        return jsonify({'message': 'Unauthorized'}), 401

    access_key_id, secret_access_key, region = get_user_credentials(username)
    if not all([access_key_id, secret_access_key, region]):
        return jsonify({'message': 'AWS credentials not found'}), 404

    try:
        codedeploy_client = boto3.client(
            'codedeploy',
            aws_access_key_id=access_key_id,
            aws_secret_access_key=secret_access_key,
            region_name=region
        )
        response = codedeploy_client.delete_application(
            applicationName=application_name
        )
        return jsonify({'message': 'Application deleted successfully', 'response': response}), 200
    except (NoCredentialsError, PartialCredentialsError) as e:
        return jsonify({'message': 'AWS credentials error', 'error': str(e)}), 400
    except ClientError as e:
        return jsonify({'message': 'Failed to delete application', 'error': str(e)}), 500

@app.route('/codedeploy/list-applications', methods=['GET'])
def list_applications():
    # Fetch AWS credentials from MongoDB
    username = session.get('username')
    if not username:
        return jsonify({'message': 'Unauthorized'}), 401

    access_key_id, secret_access_key, region = get_user_credentials(username)
    if not all([access_key_id, secret_access_key, region]):
        return jsonify({'message': 'AWS credentials not found'}), 404

    try:
        codedeploy_client = boto3.client(
            'codedeploy',
            aws_access_key_id=access_key_id,
            aws_secret_access_key=secret_access_key,
            region_name=region
        )
        response = codedeploy_client.list_applications()
        return jsonify({'message': 'Applications listed successfully', 'response': response}), 200
    except (NoCredentialsError, PartialCredentialsError) as e:
        return jsonify({'message': 'AWS credentials error', 'error': str(e)}), 400
    except ClientError as e:
        return jsonify({'message': 'Failed to list applications', 'error': str(e)}), 500

##### code commit code 

@app.route('/codecommit')
def codecommit():
    return render_template('codecommit.html')

# Create a new CodeCommit repository
@app.route('/create-repo', methods=['POST'])
def create_repo():
    data = request.get_json()
    repo_name = data.get('repositoryName')
    if not repo_name:
        return jsonify({"error": "repositoryName is required"}), 400

    # Fetch AWS credentials from MongoDB
    username = session.get('username')
    if not username:
        return jsonify({'message': 'Unauthorized'}), 401

    access_key_id, secret_access_key, region = get_user_credentials(username)
    if not all([access_key_id, secret_access_key, region]):
        return jsonify({'message': 'AWS credentials not found'}), 404

    try:
        codecommit_client = boto3.client(
            'codecommit',
            aws_access_key_id=access_key_id,
            aws_secret_access_key=secret_access_key,
            region_name=region
        )
        response = codecommit_client.create_repository(
            repositoryName=repo_name,
            repositoryDescription=data.get('repositoryDescription', '')
        )
        return jsonify({'message': 'Repository created successfully', 'response': response}), 201
    except (NoCredentialsError, PartialCredentialsError) as e:
        return jsonify({'message': 'AWS credentials error', 'error': str(e)}), 400
    except ClientError as e:
        return jsonify({'message': 'Failed to create repository', 'error': str(e)}), 500

# Get information about a CodeCommit repository
@app.route('/get-repo', methods=['GET'])
def get_repo():
    repo_name = request.args.get('repositoryName')
    if not repo_name:
        return jsonify({"error": "repositoryName is required"}), 400

    # Fetch AWS credentials from MongoDB
    username = session.get('username')
    if not username:
        return jsonify({'message': 'Unauthorized'}), 401

    access_key_id, secret_access_key, region = get_user_credentials(username)
    if not all([access_key_id, secret_access_key, region]):
        return jsonify({'message': 'AWS credentials not found'}), 404

    try:
        codecommit_client = boto3.client(
            'codecommit',
            aws_access_key_id=access_key_id,
            aws_secret_access_key=secret_access_key,
            region_name=region
        )
        response = codecommit_client.get_repository(
            repositoryName=repo_name
        )
        return jsonify({'message': 'Repository fetched successfully', 'response': response}), 200
    except (NoCredentialsError, PartialCredentialsError) as e:
        return jsonify({'message': 'AWS credentials error', 'error': str(e)}), 400
    except ClientError as e:
        return jsonify({'message': 'Failed to fetch repository', 'error': str(e)}), 500

# Delete a CodeCommit repository
@app.route('/delete-repo', methods=['DELETE'])
def delete_repo():
    data = request.get_json()
    repo_name = data.get('repositoryName')
    if not repo_name:
        return jsonify({"error": "repositoryName is required"}), 400

    # Fetch AWS credentials from MongoDB
    username = session.get('username')
    if not username:
        return jsonify({'message': 'Unauthorized'}), 401

    access_key_id, secret_access_key, region = get_user_credentials(username)
    if not all([access_key_id, secret_access_key, region]):
        return jsonify({'message': 'AWS credentials not found'}), 404

    try:
        codecommit_client = boto3.client(
            'codecommit',
            aws_access_key_id=access_key_id,
            aws_secret_access_key=secret_access_key,
            region_name=region
        )
        response = codecommit_client.delete_repository(
            repositoryName=repo_name
        )
        return jsonify({'message': 'Repository deleted successfully', 'response': response}), 200
    except (NoCredentialsError, PartialCredentialsError) as e:
        return jsonify({'message': 'AWS credentials error', 'error': str(e)}), 400
    except ClientError as e:
        return jsonify({'message': 'Failed to delete repository', 'error': str(e)}), 500

# List all CodeCommit repositories
@app.route('/list-repos', methods=['GET'])
def list_repos():
    # Fetch AWS credentials from MongoDB
    username = session.get('username')
    if not username:
        return jsonify({'message': 'Unauthorized'}), 401

    access_key_id, secret_access_key, region = get_user_credentials(username)
    if not all([access_key_id, secret_access_key, region]):
        return jsonify({'message': 'AWS credentials not found'}), 404

    try:
        codecommit_client = boto3.client(
            'codecommit',
            aws_access_key_id=access_key_id,
            aws_secret_access_key=secret_access_key,
            region_name=region
        )
        response = codecommit_client.list_repositories()
        return jsonify({'message': 'Repositories listed successfully', 'response': response}), 200
    except (NoCredentialsError, PartialCredentialsError) as e:
        return jsonify({'message': 'AWS credentials error', 'error': str(e)}), 400
    except ClientError as e:
        return jsonify({'message': 'Failed to list repositories', 'error': str(e)}), 500
    

#### iam user

@app.route('/iam')
def iam():
    return render_template('iam.html')

@app.route('/create_user', methods=['POST'])
def create_user():
    new_username = request.json.get('username')

    # Fetch AWS credentials from MongoDB
    username = session.get('username')
    if not username:
        return jsonify({'message': 'Unauthorized'}), 401

    access_key_id, secret_access_key, region = get_user_credentials(username)
    if not all([access_key_id, secret_access_key, region]):
        return jsonify({'message': 'AWS credentials not found'}), 404

    try:
        iam_client = boto3.client(
            'iam',
            aws_access_key_id=access_key_id,
            aws_secret_access_key=secret_access_key,
            region_name=region
        )
        response = iam_client.create_user(UserName=new_username)
        return jsonify({'message': 'User created successfully', 'user': response['User']}), 201
    except (NoCredentialsError, PartialCredentialsError) as e:
        return jsonify({'message': 'AWS credentials error', 'error': str(e)}), 400
    except ClientError as e:
        return jsonify({'message': 'Failed to create user', 'error': str(e)}), 500

@app.route('/delete_user', methods=['DELETE'])
def delete_user():
    del_username = request.json.get('username')

    # Fetch AWS credentials from MongoDB
    username = session.get('username')
    if not username:
        return jsonify({'message': 'Unauthorized'}), 401

    access_key_id, secret_access_key, region = get_user_credentials(username)
    if not all([access_key_id, secret_access_key, region]):
        return jsonify({'message': 'AWS credentials not found'}), 404

    try:
        iam_client = boto3.client(
            'iam',
            aws_access_key_id=access_key_id,
            aws_secret_access_key=secret_access_key,
            region_name=region
        )
        response = iam_client.delete_user(UserName=del_username)
        return jsonify({'message': 'User deleted successfully'}), 200
    except (NoCredentialsError, PartialCredentialsError) as e:
        return jsonify({'message': 'AWS credentials error', 'error': str(e)}), 400
    except ClientError as e:
        return jsonify({'message': 'Failed to delete user', 'error': str(e)}), 500

@app.route('/list_users', methods=['GET'])
def list_users():

    # Fetch AWS credentials from MongoDB
    username = session.get('username')
    if not username:
        return jsonify({'message': 'Unauthorized'}), 401

    access_key_id, secret_access_key, region = get_user_credentials(username)
    if not all([access_key_id, secret_access_key, region]):
        return jsonify({'message': 'AWS credentials not found'}), 404

    try:
        iam_client = boto3.client(
            'iam',
            aws_access_key_id=access_key_id,
            aws_secret_access_key=secret_access_key,
            region_name=region
        )
        response = iam_client.list_users()
        return jsonify({'message': 'Users listed successfully', 'users': response['Users']}), 200
    except (NoCredentialsError, PartialCredentialsError) as e:
        return jsonify({'message': 'AWS credentials error', 'error': str(e)}), 400
    except ClientError as e:
        return jsonify({'message': 'Failed to list users', 'error': str(e)}), 500

@app.route('/create_group', methods=['POST'])
def create_group():
    groupname = request.json.get('groupname')

    # Fetch AWS credentials from MongoDB
    username = session.get('username')
    if not username:
        return jsonify({'message': 'Unauthorized'}), 401

    access_key_id, secret_access_key, region = get_user_credentials(username)
    if not all([access_key_id, secret_access_key, region]):
        return jsonify({'message': 'AWS credentials not found'}), 404

    try:
        iam_client = boto3.client(
            'iam',
            aws_access_key_id=access_key_id,
            aws_secret_access_key=secret_access_key,
            region_name=region
        )
        response = iam_client.create_group(GroupName=groupname)
        return jsonify({'message': 'Group created successfully', 'group': response['Group']}), 201
    except (NoCredentialsError, PartialCredentialsError) as e:
        return jsonify({'message': 'AWS credentials error', 'error': str(e)}), 400
    except ClientError as e:
        return jsonify({'message': 'Failed to create group', 'error': str(e)}), 500

@app.route('/list_groups', methods=['GET'])
def list_groups():

    # Fetch AWS credentials from MongoDB
    username = session.get('username')
    if not username:
        return jsonify({'message': 'Unauthorized'}), 401

    access_key_id, secret_access_key, region = get_user_credentials(username)
    if not all([access_key_id, secret_access_key, region]):
        return jsonify({'message': 'AWS credentials not found'}), 404

    try:
        iam_client = boto3.client(
            'iam',
            aws_access_key_id=access_key_id,
            aws_secret_access_key=secret_access_key,
            region_name=region
        )
        response = iam_client.list_groups()
        return jsonify({'message': 'Groups listed successfully', 'groups': response['Groups']}), 200
    except (NoCredentialsError, PartialCredentialsError) as e:
        return jsonify({'message': 'AWS credentials error', 'error': str(e)}), 400
    except ClientError as e:
        return jsonify({'message': 'Failed to list groups', 'error': str(e)}), 500

@app.route('/delete_group', methods=['DELETE'])
def delete_group():
    groupname = request.json.get('groupname')

    # Fetch AWS credentials from MongoDB
    username = session.get('username')
    if not username:
        return jsonify({'message': 'Unauthorized'}), 401

    access_key_id, secret_access_key, region = get_user_credentials(username)
    if not all([access_key_id, secret_access_key, region]):
        return jsonify({'message': 'AWS credentials not found'}), 404

    try:
        iam_client = boto3.client(
            'iam',
            aws_access_key_id=access_key_id,
            aws_secret_access_key=secret_access_key,
            region_name=region
        )
        response = iam_client.delete_group(GroupName=groupname)
        return jsonify({'message': 'Group deleted successfully'}), 200
    except (NoCredentialsError, PartialCredentialsError) as e:
        return jsonify({'message': 'AWS credentials error', 'error': str(e)}), 400
    except ClientError as e:
        return jsonify({'message': 'Failed to delete group', 'error': str(e)}), 500


#### cloudformation code

@app.route('/cloudformation')
def cloudformation():
    return render_template('cloudformation.html')

@app.route('/create_stack', methods=['POST'])
def create_stack():
    stack_name = request.form.get('stack_name')
    template_file = request.files.get('template_file')

    if not stack_name or not template_file:
        return jsonify({'message': 'stack_name and template_file are required'}), 400

    template_body = template_file.read().decode('utf-8')

    # Fetch AWS credentials from MongoDB
    username = session.get('username')
    if not username:
        return jsonify({'message': 'Unauthorized'}), 401

    access_key_id, secret_access_key, region = get_user_credentials(username)
    if not all([access_key_id, secret_access_key, region]):
        return jsonify({'message': 'AWS credentials not found'}), 404

    try:
        cloudformation_client = boto3.client(
            'cloudformation',
            aws_access_key_id=access_key_id,
            aws_secret_access_key=secret_access_key,
            region_name=region
        )
        response = cloudformation_client.create_stack(
            StackName=stack_name,
            TemplateBody=template_body,
            Capabilities=['CAPABILITY_NAMED_IAM']
        )
        return jsonify({'message': 'Stack creation initiated', 'stack_id': response['StackId']}), 200
    except (NoCredentialsError, PartialCredentialsError) as e:
        return jsonify({'message': 'AWS credentials error', 'error': str(e)}), 400
    except ClientError as e:
        return jsonify({'message': 'Failed to create stack', 'error': str(e)}), 500

@app.route('/delete_stack', methods=['POST'])
def delete_stack():
    stack_name = request.form.get('stack_name')

    if not stack_name:
        return jsonify({'message': 'stack_name is required'}), 400

    # Fetch AWS credentials from MongoDB
    username = session.get('username')
    if not username:
        return jsonify({'message': 'Unauthorized'}), 401

    access_key_id, secret_access_key, region = get_user_credentials(username)
    if not all([access_key_id, secret_access_key, region]):
        return jsonify({'message': 'AWS credentials not found'}), 404

    try:
        cloudformation_client = boto3.client(
            'cloudformation',
            aws_access_key_id=access_key_id,
            aws_secret_access_key=secret_access_key,
            region_name=region
        )
        response = cloudformation_client.delete_stack(StackName=stack_name)
        return jsonify({'message': 'Stack deletion initiated'}), 200
    except (NoCredentialsError, PartialCredentialsError) as e:
        return jsonify({'message': 'AWS credentials error', 'error': str(e)}), 400
    except ClientError as e:
        return jsonify({'message': 'Failed to delete stack', 'error': str(e)}), 500

@app.route('/list_stacks', methods=['GET'])
def list_stacks():
    # Fetch AWS credentials from MongoDB
    username = session.get('username')
    if not username:
        return jsonify({'message': 'Unauthorized'}), 401

    access_key_id, secret_access_key, region = get_user_credentials(username)
    if not all([access_key_id, secret_access_key, region]):
        return jsonify({'message': 'AWS credentials not found'}), 404

    try:
        cloudformation_client = boto3.client(
            'cloudformation',
            aws_access_key_id=access_key_id,
            aws_secret_access_key=secret_access_key,
            region_name=region
        )
        response = cloudformation_client.list_stacks(
            StackStatusFilter=[
                'CREATE_IN_PROGRESS', 'CREATE_FAILED', 'CREATE_COMPLETE',
                'ROLLBACK_IN_PROGRESS', 'ROLLBACK_FAILED', 'ROLLBACK_COMPLETE',
                'DELETE_IN_PROGRESS', 'DELETE_FAILED', 'DELETE_COMPLETE',
                'UPDATE_IN_PROGRESS', 'UPDATE_COMPLETE_CLEANUP_IN_PROGRESS',
                'UPDATE_COMPLETE', 'UPDATE_FAILED', 'UPDATE_ROLLBACK_IN_PROGRESS',
                'UPDATE_ROLLBACK_FAILED', 'UPDATE_ROLLBACK_COMPLETE_CLEANUP_IN_PROGRESS',
                'UPDATE_ROLLBACK_COMPLETE', 'REVIEW_IN_PROGRESS', 'IMPORT_IN_PROGRESS',
                'IMPORT_COMPLETE', 'IMPORT_ROLLBACK_IN_PROGRESS', 'IMPORT_ROLLBACK_FAILED',
                'IMPORT_ROLLBACK_COMPLETE'
            ]
        )
        return jsonify(response['StackSummaries']), 200
    except (NoCredentialsError, PartialCredentialsError) as e:
        return jsonify({'message': 'AWS credentials error', 'error': str(e)}), 400
    except ClientError as e:
        return jsonify({'message': 'Failed to list stacks', 'error': str(e)}), 500




if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)

