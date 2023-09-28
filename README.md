## Install jnetpcap local repo

for linux, sudo is a prerequisite
```
//linux :at the pathtoproject/jnetpcap/linux/jnetpcap-1.4.r1425
//windows: at the pathtoproject/jnetpcap/win/jnetpcap-1.4.r1425
mvn install:install-file -Dfile=jnetpcap.jar -DgroupId=org.jnetpcap -DartifactId=jnetpcap -Dversion=1.4.1 -Dpackaging=jar
```

## Run
### IntelliJ IDEA
open a Terminal in the IDE
```
//linux:
$ sudo bash
$ ./gradlew execute

//windows:
$ gradlew execute
```
### Eclipse

Run eclipse with sudo
```
1. Right click App.java -> Run As -> Run Configurations -> Arguments -> VM arguments:
-Djava.library.path="pathtoproject/jnetpcap/linux/jnetpcap-1.4.r1425"  -> Run

2. Right click App.java -> Run As -> Java Application

```

## Make package

### IntelliJ IDEA
open a Terminal in the IDE
```
//linux:
$ ./gradlew distZip
//window
$ gradlew distZip
```
the zip file will be in the pathtoproject/CICFlowMeter/build/distributions

### Eclipse
At the project root
```
mvn package
```
the jar file will be in the pathtoproject/CICFlowMeter/target

## Packet Analyzer 실행 방법
1. gpu-union 접속
2. 네트워크 AI 실행
```
$ cd /home/gpu-union/src/intrusion-detection-systems/api
$ uvicorn dnnFastApi:app
```
3. CIC Packe Analyzer 실행
```
$ cd /home/gpu-union/network_ai/CICFlowMeter
$ sudo ./gradlew exeNSLKDDFlowMeter -PnetworkIF=wlo1
```

## Packet Analyzer 테스트를 위한 패킷 발생
1. rnd1-union 접속
2. 패킷 발생 시뮬레이터 실행
```
$ cd /home/rnd1-union/sim/network_sim
$  
```
