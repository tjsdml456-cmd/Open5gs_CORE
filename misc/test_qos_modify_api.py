#!/usr/bin/env python3
"""
Simple test script for qos-modify API using httpx (HTTP/2)
"""
import sys
import json

try:
    import httpx
except ImportError:
    print("ERROR: httpx 모듈이 필요합니다")
    print("설치: pip3 install httpx --break-system-packages")
    sys.exit(1)

# SMF API 설정
SMF_API = "http://127.0.0.4:7777/nsmf-pdusession/v1/qos-modify"

# 테스트 데이터
test_data = {
    "supi": "imsi-001010123456780",
    "psi": 1,
    "qfi": 1,
    "5qi": 3,
    "gbr_dl": 5000000,
    "gbr_ul": 5000000
}

def test_qos_modify():
    print(f"[TEST] Sending POST request to {SMF_API}")
    print(f"[TEST] Request data: {json.dumps(test_data, indent=2)}")
    
    try:
        # HTTP/2 클라이언트 생성
        with httpx.Client(http2=True, timeout=10.0) as client:
            response = client.post(
                SMF_API,
                headers={"Content-Type": "application/json"},
                json=test_data
            )
            
            print(f"[RESULT] HTTP Status: {response.status_code}")
            print(f"[RESULT] Response headers: {dict(response.headers)}")
            
            if response.text:
                print(f"[RESULT] Response body: {response.text}")
            
            if response.status_code in [200, 204]:
                print("[SUCCESS] QoS modify request succeeded!")
                return 0
            else:
                print(f"[ERROR] QoS modify request failed with status {response.status_code}")
                return 1
                
    except httpx.HTTPError as e:
        print(f"[ERROR] HTTP error: {e}")
        return 1
    except Exception as e:
        print(f"[ERROR] Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        return 1

if __name__ == "__main__":
    sys.exit(test_qos_modify())

