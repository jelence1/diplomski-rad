import json
import requests
import time
import os

BUCKET = os.getenv('BUCKET')
ORG = os.getenv('ORG')
INFLUXDB_URL = os.getenv('INFLUXDB_URL')
TOKEN = os.getenv('TOKEN')

def lambda_handler(event, context):
    try:
        measurement = 'esp32'
        timestamp = event["timestamp"]
        device_id = event["device_id"]
        event_data = event["data"]
        fields = ",".join([f"{key}={value}" for key, value in event_data.items() if key != "timestamp" and key != "device_id"])
        data = f"{measurement},device_id={device_id} {fields} {timestamp}"
        print(data)
        headers = {
                'Authorization': f'Token {TOKEN}',
                'Content-Type': 'text/plain'
            }
        params = {
            'org': ORG,
            'bucket': BUCKET,
            'precision': 'ms'
        }
        response = requests.post(
                INFLUXDB_URL,
                headers=headers,
                data=data,
                params=params
            )
        response.raise_for_status()
        print("Data sent to InfluxDB successfully")
    except Exception as e:
        print("Error:", e)
        
    return {
        'statusCode': 200,
        'body': json.dumps('Data processed and sent to InfluxDB')
    }