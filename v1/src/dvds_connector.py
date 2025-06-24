#!/usr/bin/env python3
"""수정된 DVDS 연결 및 제어"""

import subprocess
import time
import requests
import json
import os
import signal

class DVDSConnector:
    def __init__(self, dvds_path):
        self.dvds_path = dvds_path
        self.process = None
        self.docker_process = None
        self.port = 8080
        self.management_port = 5000
        
    def start_dvds(self):
        """DVDS 시작"""
        print(f"🎯 DVDS 시작 중... (경로: {self.dvds_path})")
        
        # Docker Compose로 시도
        if self.start_with_docker():
            return True
            
        # Python 직접 실행으로 시도
        if self.start_with_python():
            return True
            
        print("❌ DVDS 시작 실패")
        return False
    
    def start_with_docker(self):
        """Docker Compose로 DVDS 시작"""
        try:
            print("🐳 Docker Compose로 DVDS 시작 시도...")
            
            # Docker 상태 확인
            result = subprocess.run(['docker', '--version'], 
                                  capture_output=True, text=True)
            if result.returncode != 0:
                print("Docker가 설치되지 않음")
                return False
            
            # DVDS 시작 스크립트 사용
            start_script = os.path.join(self.dvds_path, 'start.sh')
            if os.path.exists(start_script):
                print("DVDS 공식 시작 스크립트 사용")
                result = subprocess.run(['sudo', start_script], 
                                      cwd=self.dvds_path,
                                      capture_output=True, text=True)
                if result.returncode == 0:
                    time.sleep(10)
                    if self.test_connection():
                        print("✅ DVDS가 성공적으로 시작됨")
                        return True
            
            # Docker Compose 직접 실행
            compose_file = os.path.join(self.dvds_path, 'docker-compose.yaml')
            if os.path.exists(compose_file):
                print("Docker Compose 직접 실행")
                result = subprocess.run(['sudo', 'docker-compose', 'up', '-d'],
                                      cwd=self.dvds_path,
                                      capture_output=True, text=True)
                if result.returncode == 0:
                    time.sleep(10)
                    if self.test_connection():
                        print("✅ DVDS Docker Compose 성공")
                        return True
            
            return False
                
        except Exception as e:
            print(f"Docker 시작 실패: {e}")
            return False
    
    def start_with_python(self):
        """Python Flask 앱으로 직접 시작"""
        try:
            print("🐍 Python Flask로 DVDS 시작 시도...")
            
            # 시뮬레이터 mgmt 앱 경로
            mgmt_path = os.path.join(self.dvds_path, 'simulator', 'mgmt')
            app_file = os.path.join(mgmt_path, 'app.py')
            
            if not os.path.exists(app_file):
                print(f"Flask 앱 파일이 없음: {app_file}")
                return False
            
            # Flask 앱 실행
            env = os.environ.copy()
            env['FLASK_APP'] = 'app.py'
            env['FLASK_ENV'] = 'development'
            
            self.process = subprocess.Popen(
                ['python3', '-m', 'flask', 'run', 
                 '--host=0.0.0.0', f'--port={self.management_port}'],
                cwd=mgmt_path,
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            
            # 시작 대기
            time.sleep(5)
            
            # 연결 테스트
            if self.test_flask_connection():
                print(f"✅ DVDS Flask 앱 성공적으로 시작됨 (포트: {self.management_port})")
                return True
            else:
                print("Flask 앱으로 시작했지만 연결 실패")
                self.stop_python()
                return False
                
        except Exception as e:
            print(f"Python Flask 시작 실패: {e}")
            return False
    
    def test_connection(self):
        """기본 포트 연결 테스트"""
        ports_to_test = [8080, 8081, 5000, 3000]
        
        for port in ports_to_test:
            try:
                response = requests.get(f'http://localhost:{port}', timeout=3)
                if response.status_code == 200:
                    self.port = port
                    print(f"DVDS가 포트 {port}에서 응답함")
                    return True
            except:
                continue
        return False
    
    def test_flask_connection(self):
        """Flask 앱 연결 테스트"""
        try:
            response = requests.get(f'http://localhost:{self.management_port}', timeout=5)
            return response.status_code == 200
        except:
            return False
    
    def stop_dvds(self):
        """DVDS 중지"""
        try:
            # DVDS 공식 중지 스크립트 사용
            stop_script = os.path.join(self.dvds_path, 'stop.sh')
            if os.path.exists(stop_script):
                subprocess.run(['sudo', stop_script], cwd=self.dvds_path)
                print("🛑 DVDS 중지됨 (공식 스크립트)")
            
            # Docker Compose 중지
            compose_file = os.path.join(self.dvds_path, 'docker-compose.yaml')
            if os.path.exists(compose_file):
                subprocess.run(['sudo', 'docker-compose', 'down'], 
                             cwd=self.dvds_path)
                print("🐳 Docker Compose 중지됨")
                
        except Exception as e:
            print(f"DVDS 중지 실패: {e}")
        
        # Python 프로세스 중지
        self.stop_python()
    
    def stop_python(self):
        """Python 프로세스 중지"""
        if self.process:
            try:
                self.process.terminate()
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
            except Exception as e:
                print(f"Python 프로세스 중지 실패: {e}")
            finally:
                self.process = None
            print("🐍 Python DVDS 중지됨")

def main():
    import sys
    dvds_path = sys.argv[1] if len(sys.argv) > 1 else "external/dvds"
    
    connector = DVDSConnector(dvds_path)
    
    try:
        if connector.start_dvds():
            print("✅ DVDS가 성공적으로 시작됨")
            print(f"웹 인터페이스: http://localhost:{connector.port}")
            print("Ctrl+C로 중지하세요...")
            
            while True:
                time.sleep(1)
        else:
            print("❌ DVDS 시작 실패")
            
    except KeyboardInterrupt:
        print("\n중지 중...")
        connector.stop_dvds()

if __name__ == "__main__":
    main()