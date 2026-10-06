from flask import Flask, jsonify, request, send_from_directory
import mysql.connector
import os
import boto3
from dotenv import load_dotenv
from werkzeug.security import generate_password_hash, check_password_hash
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from werkzeug.utils import secure_filename
from io import BytesIO
from flask import send_file

load_dotenv()

app = Flask(__name__)

b2 = boto3.client(
    "s3",
    endpoint_url=os.getenv("B2_ENDPOINT"),
    aws_access_key_id=os.getenv("B2_KEY_ID"),
    aws_secret_access_key=os.getenv("B2_APPLICATION_KEY"),
    region_name=os.getenv("B2_REGION")
)

B2_BUCKET = os.getenv("B2_BUCKET_NAME")

app.config["JWT_SECRET_KEY"] = "change-this-secret-key"
jwt = JWTManager(app)

db = mysql.connector.connect(
    host=os.getenv("DB_HOST"),
    port=int(os.getenv("DB_PORT", "3306")),
    user=os.getenv("DB_USER"),
    password=os.getenv("DB_PASSWORD"),
    database=os.getenv("DB_NAME")
)
 
@app.route("/api/register", methods=["POST"])
def register():

    data = request.get_json()

    name = data.get("name")
    email = data.get("email")
    password = data.get("password")

    if not name or not email or not password:
        return jsonify({
            "error": "Name, email and password are required"
        }), 400

    password_hash = generate_password_hash(password)

    cursor = db.cursor()

    query = """
        INSERT INTO personal (Name, Email, PasswordHash)
        VALUES (%s, %s, %s)
    """

    cursor.execute(query, (name, email, password_hash))
    db.commit()

    cursor.close()

    return jsonify({
        "message": "User registered successfully"
    }), 201

@app.route("/api/login", methods=["POST"])
def login():

    data = request.get_json()

    email = data.get("email")
    password = data.get("password")

    if not email or not password:
        return jsonify({
            "error": "Email and password are required"
        }), 400

    cursor = db.cursor(dictionary=True)

    query = "SELECT * FROM personal WHERE Email = %s"

    cursor.execute(query, (email,))

    user = cursor.fetchone()

    cursor.close()

    if not user:
        return jsonify({
            "error": "Invalid email or password"
        }), 401

    if not check_password_hash(user["PasswordHash"], password):
        return jsonify({
            "error": "Invalid email or password"
        }), 401

    access_token = create_access_token(
        identity=str(user["ID"])
    )

    return jsonify({
        "message": "Login successful",
        "access_token": access_token
    }), 200

@app.route("/api/profile", methods=["GET"])
@jwt_required()
def profile():

    user_id = get_jwt_identity()

    cursor = db.cursor(dictionary=True)

    query = "SELECT ID, Name, Email FROM personal WHERE ID = %s"

    cursor.execute(query, (user_id,))

    user = cursor.fetchone()

    cursor.close()

    if not user:
        return jsonify({
            "error": "User not found"
        }), 404

    return jsonify({
        "message": "Protected API accessed successfully",
        "user": user
    })

@app.route("/api/upload", methods=["POST"])
@jwt_required()
def upload_file():

    user_id = get_jwt_identity()

    if "file" not in request.files:
        return jsonify({
            "error": "No file provided"
        }), 400

    file = request.files["file"]

    if file.filename == "":
        return jsonify({
            "error": "No file selected"
        }), 400

    filename = secure_filename(file.filename)

    if filename == "":
        return jsonify({
            "error": "Invalid filename"
        }), 400

    # Store each user's files in their own folder in B2
    object_key = f"{user_id}/{filename}"

    try:
        b2.upload_fileobj(
            file,
            B2_BUCKET,
            object_key,
            ExtraArgs={
                "ContentType": file.content_type or "application/octet-stream"
            }
        )

        cursor = db.cursor()

        query = """
            INSERT INTO files (user_id, filename, file_path)
            VALUES (%s, %s, %s)
        """

        cursor.execute(
            query,
            (user_id, filename, object_key)
        )

        db.commit()
        cursor.close()

        return jsonify({
            "message": "File uploaded to Backblaze B2 successfully",
            "filename": filename,
            "user_id": user_id
        }), 201

    except Exception as e:

        print("B2 Upload Error:", e)

        return jsonify({
            "error": "File upload failed"
        }), 500

@app.route("/api/files", methods=["GET"])
@jwt_required()
def get_files():

    user_id = get_jwt_identity()

    cursor = db.cursor(dictionary=True)

    query = """
        SELECT id, filename, file_path, uploaded_at
        FROM files
        WHERE user_id = %s
    """

    cursor.execute(query, (user_id,))

    files = cursor.fetchall()

    cursor.close()

    return jsonify({
        "user_id": user_id,
        "files": files
    })

@app.route("/api/download/<filename>", methods=["GET"])
@jwt_required()
def download_file(filename):

    user_id = get_jwt_identity()

    cursor = db.cursor(dictionary=True)

    query = """
        SELECT file_path
        FROM files
        WHERE filename = %s AND user_id = %s
    """

    cursor.execute(query, (filename, user_id))

    file = cursor.fetchone()

    cursor.close()

    if not file:
        return jsonify({
            "error": "File not found or you do not have access"
        }), 404

    try:
        response = b2.get_object(
            Bucket=B2_BUCKET,
            Key=file["file_path"]
        )

        file_data = response["Body"].read()

        return send_file(
            BytesIO(file_data),
            download_name=filename,
            as_attachment=True
        )

    except Exception as e:

        print("B2 Download Error:", e)

        return jsonify({
            "error": "File download failed"
        }), 500

@app.route("/api/files/<filename>", methods=["DELETE"])
@jwt_required()
def delete_file(filename):

    user_id = get_jwt_identity()

    cursor = db.cursor(dictionary=True)

    query = """
        SELECT file_path
        FROM files
        WHERE filename = %s AND user_id = %s
    """

    cursor.execute(query, (filename, user_id))
    file = cursor.fetchone()

    if not file:
        cursor.close()

        return jsonify({
            "error": "File not found or you do not have access"
        }), 404

    object_key = file["file_path"]

    try:
        # Get all versions of this object
        response = b2.list_object_versions(
            Bucket=B2_BUCKET,
            Prefix=object_key
        )

        # Delete normal versions
        for version in response.get("Versions", []):
            if version["Key"] == object_key:
                b2.delete_object(
                    Bucket=B2_BUCKET,
                    Key=object_key,
                    VersionId=version["VersionId"]
                )

        # Delete delete-markers too
        for marker in response.get("DeleteMarkers", []):
            if marker["Key"] == object_key:
                b2.delete_object(
                    Bucket=B2_BUCKET,
                    Key=object_key,
                    VersionId=marker["VersionId"]
                )

        # Delete metadata from MySQL
        delete_query = """
            DELETE FROM files
            WHERE filename = %s AND user_id = %s
        """

        cursor.execute(delete_query, (filename, user_id))

        db.commit()
        cursor.close()

        return jsonify({
            "message": "File permanently deleted",
            "filename": filename
        })

    except Exception as e:

        cursor.close()

        print("B2 Delete Error:", e)

        return jsonify({
            "error": "Permanent file deletion failed"
        }), 500

@app.route("/")
def home():
    return "Cloud File Storage API is running!"

if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=int(os.getenv("PORT", "5000")),
        debug=False
    )