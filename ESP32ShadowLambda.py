import json
import requests
import time
import os

BUCKET = os.getenv('BUCKET')
ORG = os.getenv('ORG')
INFLUXDB_URL = os.getenv('INFLUXDB_URL')
TOKEN = os.getenv('TOKEN')

def lambda_handler(event, context):
    print(event)
    if "reported" not in event["state"].keys():
        print("Desired event, skip storing")
        return
    
    try:
        print("Reported state. Trying to store...")
        measurement = 'esp32'
        timestamp = event["timestamp"]
        current_state = event["state"]["reported"]
        device_id = event["clientToken"]
        fields = ",".join([f"{key}={value}" for key, value in current_state.items() if key != "timestamp" and key != "clientToken"])
        data = f"{measurement},device_id={device_id} {fields} {timestamp}"
        print(data)
        headers = {
                'Authorization': f'Token {TOKEN}',
                'Content-Type': 'text/plain'
            }
        params = {
            'org': ORG,
            'bucket': BUCKET,
            'precision': 's'
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