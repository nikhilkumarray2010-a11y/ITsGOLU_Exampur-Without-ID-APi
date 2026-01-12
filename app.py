import os
import re
import json
import base64
import requests
from flask import Flask, request, jsonify, Response
from flask_cors import CORS
from bs4 import BeautifulSoup
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import logging
import time
from functools import wraps

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# Configure CORS
CORS(app, resources={
    r"/*": {
        "origins": "*",
        "methods": ["GET", "POST", "OPTIONS"],
        "allow_headers": ["Content-Type", "X-Requested-With", "Authorization", "Accept", "Origin"]
    }
})

# Handle preflight requests
@app.before_request
def handle_preflight():
    if request.method == "OPTIONS":
        response = Response()
        response.headers.add("Access-Control-Allow-Origin", "*")
        response.headers.add("Access-Control-Allow-Headers", "Content-Type, X-Requested-With, Authorization, Accept, Origin")
        response.headers.add("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        return response

# Error handling decorator
def handle_errors(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        try:
            return f(*args, **kwargs)
        except Exception as e:
            logger.error(f"Error in {f.__name__}: {str(e)}", exc_info=True)
            return jsonify({'success': False, 'error': str(e)}), 500
    return wrapper

# Retry decorator for API calls
def retry(max_retries=3, delay=1):
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            retries = 0
            while retries < max_retries:
                try:
                    return f(*args, **kwargs)
                except Exception as e:
                    retries += 1
                    if retries >= max_retries:
                        raise e
                    logger.warning(f"Retry {retries}/{max_retries} for {f.__name__}: {str(e)}")
                    time.sleep(delay * retries)
            return None
        return wrapper
    return decorator

# Base64 to JSON decode with padding handling
def simple_decode(base64_str):
    try:
        if not base64_str or not isinstance(base64_str, str):
            return {"error": "Invalid base64 input"}
        
        # Handle URL-safe base64 by replacing characters
        base64_str = base64_str.replace('-', '+').replace('_', '/')
        
        # Add padding if needed
        missing_padding = len(base64_str) % 4
        if missing_padding:
            base64_str += '=' * (4 - missing_padding)
        
        decoded_bytes = base64.b64decode(base64_str)
        decoded_str = decoded_bytes.decode('utf-8')
        return json.loads(decoded_str)
    except Exception as e:
        logger.error(f"Decoding error: {str(e)}")
        return {"error": f"Decoding failed: {str(e)}"}

# JSON to Base64 encode without spaces
def simple_encode_without_spaces(data_dict):
    try:
        json_str = json.dumps(data_dict, separators=(',', ':'))
        encoded_bytes = base64.b64encode(json_str.encode('utf-8'))
        return encoded_bytes.decode('utf-8')
    except Exception as e:
        logger.error(f"Encoding error: {str(e)}")
        return None

# Encrypt stream using AES - Enhanced version
def encrypt_stream(plain_text):
    try:
        if not plain_text:
            logger.error("Empty plain_text provided to encrypt_stream")
            return None
            
        logger.info(f"Encrypting data: {plain_text[:50]}...")
        
        # Ensure key and iv are 16 bytes (AES block size)
        key = b'%!$!%_$&!%F)&^!^'
        iv = b'#*y*#2yJ*#$wJv*v'
        
        # Pad key and iv if needed
        key = key.ljust(16, b'\0')[:16]
        iv = iv.ljust(16, b'\0')[:16]
        
        logger.info(f"Using key: {key.hex()}, IV: {iv.hex()}")
        
        cipher = AES.new(key, AES.MODE_CBC, iv)
        encrypted = cipher.encrypt(pad(plain_text.encode('utf-8'), AES.block_size))
        result = base64.b64encode(encrypted).decode('utf-8')
        
        logger.info(f"Encryption successful, result length: {len(result)}")
        return result
    except Exception as e:
        logger.error(f"Encryption error: {str(e)}", exc_info=True)
        return None

# Get CSRF token and session with retry
@retry(max_retries=3, delay=1)
def get_csrf_session():
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
        }
        
        response = requests.get('https://exampur.videocrypt.in', headers=headers, timeout=30)
        response.raise_for_status()
        
        cookies = response.cookies.get_dict()
        
        csrf_token = cookies.get('csrf_name', '')
        ci_session = cookies.get('ci_session', '')
        
        if not csrf_token or not ci_session:
            raise Exception("Missing CSRF or session cookie.")
        
        logger.info(f"Successfully obtained CSRF token and session")
        return {"csrfToken": csrf_token, "ciSession": ci_session}
    except Exception as e:
        logger.error(f"Failed to get CSRF session: {str(e)}", exc_info=True)
        raise Exception(f"Failed to get CSRF session: {str(e)}")

# Get course batches with retry
@retry(max_retries=3, delay=1)
def get_course_batches(csrf_token, ci_session):
    try:
        cookies = f"csrf_name={csrf_token}; ci_session={ci_session}"
        headers = {
            'Accept': 'application/json, text/javascript, */*; q=0.01',
            'X-Requested-With': 'XMLHttpRequest',
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36',
            'Cookie': cookies
        }
        
        course_types = ['Paid Courses', 'Recorded Courses']
        batches = []
        
        for course_type in course_types:
            data = {
                'subcate': '12111',
                'course_type_master': course_type,
                'course_type': '7034',
                'csrf_name': csrf_token,
            }
            
            response = requests.post(
                'https://exampur.videocrypt.in/web/Course/getTypeCourses1',
                data=data,
                headers=headers,
                timeout=30
            )
            response.raise_for_status()
            
            if response.json() and response.json().get('response'):
                encoded_data = response.json().get('response')
                decoded = simple_decode(encoded_data)
                
                if decoded and isinstance(decoded, list):
                    for course in decoded:
                        batches.append({
                            'id': course.get('id'),
                            'title': course.get('title'),
                            'thumbnail': course.get('cover_image'),
                            'mrp': course.get('mrp'),
                            'price': course.get('course_sp'),
                            'validity': course.get('validity'),
                        })
        
        logger.info(f"Successfully fetched {len(batches)} batches")
        return batches
    except Exception as e:
        logger.error(f"Failed to get course batches: {str(e)}", exc_info=True)
        raise Exception(f"Failed to get course batches: {str(e)}")

# Get tile_id for a course - Enhanced with retry
@retry(max_retries=3, delay=1)
def get_tile_id_for_course(csrf_token, ci_session, course_id):
    try:
        cookies = f"csrf_name={csrf_token}; ci_session={ci_session}"
        
        # Try multiple approaches to get the tile_id
        
        # Approach 1: Direct API call to get course details
        try:
            headers = {
                'Cookie': cookies,
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36',
            }
            
            response = requests.get(
                f"https://exampur.videocrypt.in/web/Course/course_view/{course_id}",
                headers=headers,
                timeout=30
            )
            response.raise_for_status()
            
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Try to extract tile_id from JavaScript variables
            script_tags = soup.find_all('script')
            for script in script_tags:
                if script.string and 'tile_id' in script.string:
                    tile_id_match = re.search(r'tile_id\s*[:=]\s*["\']?(\d+)["\']?', script.string)
                    if tile_id_match:
                        tile_id = tile_id_match.group(1)
                        logger.info(f"Found tile_id via script: {tile_id}")
                        return tile_id
            
            # Try to find tile_id in hidden inputs
            hidden_inputs = soup.find_all('input', {'type': 'hidden'})
            for input_tag in hidden_inputs:
                name = input_tag.get('name')
                value = input_tag.get('value')
                if name == 'tile_id' and value:
                    logger.info(f"Found tile_id via hidden input: {value}")
                    return value
        except Exception as e:
            logger.error(f"Approach 1 failed: {str(e)}")
        
        # Approach 2: Try common tile_id values
        common_tile_ids = ['75536', '75537', '75538', '75539', '75540']
        
        for tile_id in common_tile_ids:
            try:
                logger.info(f"Trying common tile_id: {tile_id}")
                
                test_payload = {
                    "course_id": course_id,
                    "revert_api": "1#0#0#1",
                    "tile_id": tile_id,
                    "layer": 1,
                    "parent_id": "0",
                    "type": "course_combo",
                    "page": 1,
                }
                
                encrypted_input = encrypt_stream(json.dumps(test_payload))
                
                if not encrypted_input:
                    logger.error(f"Encryption failed for tile_id: {tile_id}")
                    continue
                
                headers = {
                    'Accept': 'application/json, text/javascript, */*; q=0.01',
                    'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
                    'Origin': 'https://exampur.videocrypt.in',
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36',
                    'X-Requested-With': 'XMLHttpRequest',
                    'Cookie': cookies
                }
                
                data = {
                    'tile_input': encrypted_input,
                    'csrf_name': csrf_token,
                }
                
                response = requests.post(
                    "https://exampur.videocrypt.in/web/Course/tiles_data",
                    data=data,
                    headers=headers,
                    timeout=30
                )
                
                if response.status_code == 200 and response.json() and response.json().get('response'):
                    decoded = simple_decode(response.json().get('response'))
                    if decoded and not decoded.get('error') and decoded.get('status') is not False:
                        logger.info(f"Successfully found working tile_id: {tile_id}")
                        return tile_id
            except Exception as e:
                logger.error(f"Test failed for tile_id {tile_id}: {str(e)}")
        
        # If all approaches fail, use the default
        logger.info("Using default tile_id: 75536")
        return '75536'
    except Exception as e:
        logger.error(f"Error getting tile_id: {str(e)}", exc_info=True)
        return '75536'  # Default fallback

# Fetch batch content - Enhanced with retry
@retry(max_retries=3, delay=1)
def fetch_batch_content(csrf_token, ci_session, course_id):
    try:
        cookies = f"csrf_name={csrf_token}; ci_session={ci_session}"
        
        # Get the correct tile_id for this course
        tile_id = get_tile_id_for_course(csrf_token, ci_session, course_id)
        
        tile_payload = {
            "course_id": course_id,
            "revert_api": "1#0#0#1",
            "tile_id": tile_id,
            "layer": 1,
            "parent_id": "0",
            "type": "course_combo",
            "page": 1,
        }
        
        encrypted_input = encrypt_stream(json.dumps(tile_payload))
        
        if not encrypted_input:
            raise Exception("Failed to encrypt payload")
        
        headers = {
            'Accept': 'application/json, text/javascript, */*; q=0.01',
            'Accept-Language': 'en-US,en;q=0.9',
            'Connection': 'keep-alive',
            'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
            'Origin': 'https://exampur.videocrypt.in',
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36',
            'X-Requested-With': 'XMLHttpRequest',
            'Cookie': cookies
        }
        
        data = {
            'tile_input': encrypted_input,
            'csrf_name': csrf_token,
        }
        
        response = requests.post(
            "https://exampur.videocrypt.in/web/Course/tiles_data",
            data=data,
            headers=headers,
            timeout=30
        )
        response.raise_for_status()
        
        if response.status_code == 200 and response.json() and response.json().get('response'):
            decoded = simple_decode(response.json().get('response'))
            logger.info(f"Successfully fetched content for course_id: {course_id}")
            return decoded
        else:
            logger.error(f"API Response: {json.dumps(response.json(), indent=2)}")
            raise Exception(f"Failed to fetch batch content: {response.status_code}")
    except Exception as e:
        logger.error(f"Error in fetch_batch_content: {str(e)}", exc_info=True)
        raise Exception(f"Failed to fetch batch content: {str(e)}")

# Extract data get values - Enhanced with retry
@retry(max_retries=3, delay=1)
def extract_data_get_values(csrf_token, ci_session, batch_id, course_id):
    try:
        cookies = f"csrf_name={csrf_token}; ci_session={ci_session}"
        
        data = {"course_id": course_id, "parent_id": batch_id}
        headers = {
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
            'Accept-Language': 'en-US,en;q=0.9',
            'Connection': 'keep-alive',
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36',
            'Cookie': cookies
        }
        
        enc = encrypt_stream(json.dumps(data))
        
        if not enc:
            raise Exception("Failed to encrypt data for extract_data_get_values")
            
        params = {'id': enc}
        
        response = requests.get(
            "https://exampur.videocrypt.in/web/Course/single_book_details",
            headers=headers,
            params=params,
            timeout=30
        )
        response.raise_for_status()
        
        soup = BeautifulSoup(response.text, 'html.parser')
        data_values = []
        
        # Find all anchor tags with onclick containing "ajax_get_tiles_data"
        for a_tag in soup.find_all('a', onclick=True):
            onclick_content = a_tag.get('onclick', '')
            match = re.search(r'ajax_get_tiles_data\(`([^`]+)`\)', onclick_content)
            if match:
                data_values.append(match.group(1).strip())
        
        logger.info(f"Extracted {len(data_values)} data values")
        return data_values
    except Exception as e:
        logger.error(f"Failed to extract data get values: {str(e)}", exc_info=True)
        raise Exception(f"Failed to extract data get values: {str(e)}")

# Fetch tile data from values - Enhanced with retry
@retry(max_retries=3, delay=1)
def fetch_tile_data_from_values(csrf_token, ci_session, data_get_values):
    try:
        cookies = f"csrf_name={csrf_token}; ci_session={ci_session}"
        headers = {
            'Accept': 'application/json, text/javascript, */*; q=0.01',
            'Accept-Language': 'en-US,en;q=0.9',
            'Connection': 'keep-alive',
            'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
            'Origin': 'https://exampur.videocrypt.in',
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36',
            'X-Requested-With': 'XMLHttpRequest',
            'Cookie': cookies
        }
        
        all_tile_jsons = []
        
        for tile_input in data_get_values:
            data = {
                'tile_input': tile_input,
                'csrf_name': csrf_token
            }
            
            response = requests.post(
                "https://exampur.videocrypt.in/web/Course/tiles_data",
                data=data,
                headers=headers,
                timeout=30
            )
            response.raise_for_status()
            
            if response.status_code == 200 and response.json() and response.json().get('response'):
                base64_str = response.json().get('response')
                decoded_json = simple_decode(base64_str)
                all_tile_jsons.append(decoded_json)
        
        logger.info(f"Successfully fetched {len(all_tile_jsons)} tile data")
        return all_tile_jsons
    except Exception as e:
        logger.error(f"Failed to fetch tile data from values: {str(e)}", exc_info=True)
        raise Exception(f"Failed to fetch tile data from values: {str(e)}")

# Process tile data responses
def process_tile_data_responses(tile_data_responses):
    try:
        layer_two_data = []
        
        for response in tile_data_responses:
            try:
                data = response.get('data')
                folder_id = None
                content_type = response.get('type')
                tile_id = response.get('tile_id')
                content_berdcrumb_data = response.get('content_berdcrumb_data', {})
                
                if data and isinstance(data.get('list'), list):
                    for item in data.get('list'):
                        folder_id = item.get('id')
                        if folder_id and tile_id and content_type:
                            layer_two_data.append({
                                'folder_id': folder_id,
                                'tile_id': tile_id,
                                'content_type': content_type,
                                'content_berdcrumb_data': content_berdcrumb_data
                            })
            except Exception as e:
                logger.error(f"Error processing tile response: {str(e)}", exc_info=True)
        
        logger.info(f"Processed {len(layer_two_data)} tile data responses")
        return layer_two_data
    except Exception as e:
        logger.error(f"Error in process_tile_data_responses: {str(e)}", exc_info=True)
        raise Exception(f"Error in process_tile_data_responses: {str(e)}")

# Process folder data - Enhanced with retry
@retry(max_retries=3, delay=1)
def process_folder_data(csrf_token, ci_session, folder_data, course_id, parent_id):
    try:
        cookies = f"csrf_name={csrf_token}; ci_session={ci_session}"
        headers = {
            'Accept': 'application/json, text/javascript, */*; q=0.01',
            'Accept-Language': 'en-US,en;q=0.9',
            'Connection': 'keep-alive',
            'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
            'Origin': 'https://exampur.videocrypt.in',
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36',
            'X-Requested-With': 'XMLHttpRequest',
            'Cookie': cookies
        }
        
        data_dict = {
            "course_id": course_id,
            "parent_id": parent_id,
            "layer": 2,
            "page": 1,
            "revert_api": "1#0#0#0",
            "subject_id": folder_data.get('folder_id'),
            "tile_id": folder_data.get('tile_id'),
            "topic_id": 0,
            "type": folder_data.get('content_type'),
            "content_berdcrumb_data": json.dumps(folder_data.get('content_berdcrumb_data', {}))
        }
        
        encoded_data = simple_encode_without_spaces(data_dict)
        
        if not encoded_data:
            raise Exception("Failed to encode data for process_folder_data")
        
        data = {
            'layer_two_input_data': encoded_data,
            'content': folder_data.get('content_type'),
            'csrf_name': csrf_token,
        }
        
        response = requests.post(
            'https://exampur.videocrypt.in/web/Course/get_layer_two_data',
            data=data,
            headers=headers,
            timeout=30
        )
        response.raise_for_status()
        
        if response.status_code == 200 and response.json() and response.json().get('response'):
            decoded_data = simple_decode(response.json().get('response'))
            logger.info(f"Successfully processed folder data for folder_id: {folder_data.get('folder_id')}")
            return decoded_data
        else:
            raise Exception(f"Failed to process folder data: {response.status_code}")
    except Exception as e:
        logger.error(f"Failed to process folder data: {str(e)}", exc_info=True)
        raise Exception(f"Failed to process folder data: {str(e)}")

# Health and usage info
@app.route('/')
@handle_errors
def health_check():
    return jsonify({
        'status': 'ok',
        'message': 'Server is running',
        'endpoints': [
            '/api/batches - Get all course batches',
            '/api/batch/<batchId> - Get batch content',
            '/api/course/<batchId>/<courseId> - Get course data',
            '/api/fetch_tile?csrf_token=...&batch_id=...&data_get_value=... - Fetch tile data'
        ]
    })

# Get all course batches
@app.route('/api/batches', methods=['GET'])
@handle_errors
def get_batches():
    session = get_csrf_session()
    batches = get_course_batches(session['csrfToken'], session['ciSession'])
    return jsonify({'success': True, 'data': batches})

# Get batch content
@app.route('/api/batch/<batch_id>', methods=['GET'])
@handle_errors
def get_batch_content(batch_id):
    logger.info(f"Processing batch ID: {batch_id}")
    
    session = get_csrf_session()
    content = fetch_batch_content(session['csrfToken'], session['ciSession'], batch_id)
    
    logger.info(f"Successfully fetched content for batch ID: {batch_id}")
    return jsonify({'success': True, 'data': content})

# Get course data
@app.route('/api/course/<batch_id>/<course_id>', methods=['GET'])
@handle_errors
def get_course_data(batch_id, course_id):
    session = get_csrf_session()
    
    # Extract data get values
    data_get_values = extract_data_get_values(session['csrfToken'], session['ciSession'], batch_id, course_id)
    
    # Fetch tile data
    tile_data = fetch_tile_data_from_values(session['csrfToken'], session['ciSession'], data_get_values)
    
    # Process tile data
    layer_two_data = process_tile_data_responses(tile_data)
    
    # Process each folder
    results = []
    for folder_data in layer_two_data:
        try:
            folder_content = process_folder_data(session['csrfToken'], session['ciSession'], folder_data, course_id, batch_id)
            results.append({
                'folder_id': folder_data.get('folder_id'),
                'content': folder_content
            })
        except Exception as e:
            logger.error(f"Error processing folder {folder_data.get('folder_id')}: {str(e)}", exc_info=True)
    
    return jsonify({'success': True, 'data': results})

# Support both local path and Vercel path - Fixed for Flask compatibility
@app.route('/fetch_tile', methods=['GET'])
@handle_errors
def fetch_tile():
    csrf_token = request.args.get('csrf_token', '').strip()
    batch_id = request.args.get('batch_id', '').strip()
    data_get_value = request.args.get('data_get_value', '').strip()
    
    # If data_get_value is not in the query string, try to extract it from the raw query
    if not data_get_value:
        raw_query = request.query_string.decode('utf-8')
        for part in raw_query.split('&'):
            if part.startswith('data_get_value='):
                val = part[len('data_get_value='):]
                try:
                    data_get_value = val  # Flask automatically URL decodes
                except:
                    data_get_value = val
                break
    
    # Normalize base64 segments in data_get_value
    if data_get_value:
        original = data_get_value
        try:
            parts = data_get_value.split(':')
            parts = [p.replace(' ', '+') for p in parts]
            data_get_value = ':'.join(parts)
            if original != data_get_value:
                logger.info('[Normalize] data_get_value spaces->plus applied')
        except:
            pass
    
    # Validate required params
    missing = []
    if not csrf_token:
        missing.append('csrf_token')
    if not data_get_value:
        missing.append('data_get_value')
    if not batch_id:
        missing.append('batch_id')
    
    if missing:
        return jsonify({
            'error': 'Missing required parameters',
            'missing': missing,
            'usage': '/fetch_tile?csrf_token=...&batch_id=...&data_get_value=...'
        }), 400
    
    url = 'https://exampur.videocrypt.in/web/Course/tiles_data'
    
    # Allow overrides via query/env
    override_cookie = request.args.get('cookie') or os.environ.get('UPSTREAM_COOKIE', '')
    override_referer = request.args.get('referer') or os.environ.get('UPSTREAM_REFERER', 'https://exampur.videocrypt.in/')
    override_ua = request.args.get('ua') or os.environ.get('UPSTREAM_UA', 'Mozilla/5.0')
    override_host = request.args.get('host') or os.environ.get('UPSTREAM_HOST', 'exampur.videocrypt.in')
    override_xff = request.args.get('xff') or os.environ.get('UPSTREAM_XFF', '')
    
    headers = {
        'Accept': 'application/json, text/javascript, */*; q=0.01',
        'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
        'Origin': 'https://exampur.videocrypt.in',
        'User-Agent': override_ua,
        'X-Requested-With': 'XMLHttpRequest',
        'Cookie': f"csrf_name={csrf_token}{'; ' + override_cookie if override_cookie else ''}",
        'Referer': override_referer,
        'Accept-Language': 'en-US,en;q=0.9',
        'Accept-Encoding': 'gzip, deflate, br',
        'Connection': 'keep-alive',
        'Host': override_host,
        'sec-ch-ua': '"Chromium";v="129", "Not=A?Brand";v="24", "Microsoft Edge";v="129"',
        'sec-ch-ua-mobile': '?0',
        'sec-ch-ua-platform': '"Windows"',
    }
    
    if override_xff:
        headers['X-Forwarded-For'] = override_xff
    
    form_data = {
        'tile_input': data_get_value,
        'csrf_name': csrf_token,
    }
    
    response = requests.post(
        url,
        data=form_data,
        headers=headers,
        timeout=30
    )
    
    if response.status_code == 200:
        base64_str = response.json().get('response', '') if response.json() else ''
        decoded_json = simple_decode(base64_str)
        
        if decoded_json and decoded_json.get('error'):
            return jsonify({
                'error': 'Failed to decode upstream response',
                'detail': decoded_json.get('error'),
            }), 502
        
        # convert object -> array
        if decoded_json and not isinstance(decoded_json, list) and isinstance(decoded_json, dict):
            decoded_json = [decoded_json]
        
        layer_two_data = []
        files = []
        folders = []
        
        if isinstance(decoded_json, list):
            for tile in decoded_json:
                try:
                    if isinstance(tile, str):
                        try:
                            tile = json.loads(tile)
                        except Exception as e:
                            logger.error(f"Could not convert string to JSON: {tile}", exc_info=True)
                            continue
                    
                    if not tile or not isinstance(tile, dict) or isinstance(tile, list):
                        continue
                    
                    data = tile.get('data')
                    content_type = tile.get('type')
                    tile_id = tile.get('tile_id')
                    content_berdcrumb_data = tile.get('content_berdcrumb_data', {})
                    
                    # layer two folders
                    if data and isinstance(data.get('list'), list):
                        for item in data.get('list'):
                            folder_id = item.get('id') if item else None
                            if folder_id and tile_id and content_type:
                                layer_two_data.append({
                                    'batch_id': batch_id,
                                    'folder_id': folder_id,
                                    'tile_id': tile_id,
                                    'content_type': content_type,
                                    'breadcrumb': content_berdcrumb_data,
                                })
                    
                    # get_folder -> file_result + folder_result
                    if data and data.get('get_folder'):
                        gf_data = data.get('get_folder', {}).get('data', {})
                        
                        # file_result
                        file_result = gf_data.get('file_result', [])
                        if isinstance(file_result, list):
                            files.extend(file_result)
                        elif file_result:
                            files.append(file_result)
                        
                        # folder_result
                        folder_result = gf_data.get('folder_result', [])
                        if isinstance(folder_result, list):
                            folders.extend(folder_result)
                        elif folder_result:
                            folders.append(folder_result)
                except Exception as e:
                    logger.error(f"Error processing tile response: {str(e)}", exc_info=True)
                    continue
        
        output = {
            'decoded_json': decoded_json,
            'layer_two_data': layer_two_data,
            'files': files,
            'folders': folders,
        }
        
        return jsonify(output)
    else:
        return jsonify({'error': f'HTTP {response.status_code}'}), response.status_code

# Support both local path and Vercel path - Second route for /api/fetch_tile
@app.route('/api/fetch_tile', methods=['GET'])
@handle_errors
def api_fetch_tile():
    # Just call the same function as above
    return fetch_tile()

# Main entry point
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
