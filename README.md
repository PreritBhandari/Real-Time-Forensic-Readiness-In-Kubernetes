# Real-Time Forensic Readiness in Kubernetes

This study implements a real-time forensic readiness framework in Kubernetes using Apache Cassandra and a Flask-based workload generator. The main goal is to simulate a DDoS-like query flooding attack, observe system behavior, and capture forensic evidence before pod restart happens.

---

## Tech Stack

- Kubernetes (Kind cluster)
- Apache Cassandra
- Flask (Python)
- Docker
- Prometheus & Grafana
- Apache JMeter

---

##  Project Flow

Flask App → Cassandra → High Load (JMeter) → Monitoring → Trigger → Evidence Collection

---

## Setup Instructions

### Build Flask Docker Image

docker build -t flask-forensic:v1 .

Load image into Kind cluster:

kind load docker-image flask-forensic:v1 --name forensic

---

### Deploy Cassandra & Flask

kubectl apply -f cassandra.yaml  
kubectl apply -f flask-app.yaml  

Check pods:

kubectl get pods -n forensic-lab

---

### Configure Flask Code

kubectl create configmap flask-code --from-file=app.py -n forensic-lab  
kubectl rollout restart deployment/flask-forensic-app -n forensic-lab  

---

### Access Flask API

kubectl port-forward svc/flask-service 5000:5000 -n forensic-lab  

Open browser:

http://localhost:5000

---

## Database Setup

kubectl exec -it cassandra-0 -n forensic-lab -- cqlsh -e "CREATE KEYSPACE IF NOT EXISTS forensic_lab WITH replication = {'class': 'SimpleStrategy', 'replication_factor': 1}; CREATE TABLE IF NOT EXISTS forensic_lab.activity_log (id UUID PRIMARY KEY, event_time timestamp, activity_type text);"

---

## Simulating DDoS Attack (JMeter)

### JMeter Settings

- Server: localhost  
- Port: 5000  
- Path: /attack  
- Method: POST  

### Thread Group

- Threads: 100–200+  
- Ramp-up: 10 seconds  
- Loop: Infinite  

This generates heavy load on Flask which then stresses Cassandra.

---

## Monitoring Setup

### Install Prometheus + Grafana

helm repo add prometheus-community https://prometheus-community.github.io/helm-charts  
helm repo update  
helm install monitoring prometheus-community/kube-prometheus-stack -n monitoring --create-namespace  

---

### Access Grafana

kubectl port-forward svc/monitoring-grafana 3000:80 -n monitoring  

Get password:

$encodedPassword = kubectl get secret --namespace monitoring monitoring-grafana -o jsonpath="{.data.admin-password}"  
[System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($encodedPassword))

---

### Useful Queries

container_memory_usage_bytes{pod="cassandra-0", namespace="forensic-lab"}  
kube_pod_container_status_restarts_total{pod="cassandra-0", namespace="forensic-lab"}  
container_memory_usage_bytes{pod_name=~"flask-forensic-app-.*", namespace="forensic-lab"}  
pod:container_cpu_usage:sum{pod_name=~"flask-forensic-app-.*", namespace="forensic-lab"}  

---

## Optional: Triggering Failure (OOMKill)

If incase need to manually update the memory so as to see the project output, a patch file is also included along with the project with memory configured to 800MB. 

kubectl patch statefulset cassandra -n forensic-lab --patch-file patch-attack.yaml  

This reduces memory limit and forces an OOMKilled (Exit Code 137).

---

## Running the Attack

Before running the attack, create the table:

kubectl exec -it cassandra-0 -n forensic-lab -- cqlsh -e "CREATE KEYSPACE IF NOT EXISTS forensic_lab WITH replication = {'class': 'SimpleStrategy', 'replication_factor': 1}; CREATE TABLE IF NOT EXISTS forensic_lab.activity_log (id UUID PRIMARY KEY, event_time timestamp, activity_type text);"

Start JMeter with high threads and infinite loop.

---

## Observations

Zombie State:
- Application becomes unresponsive
- Pod still shows Running
- No immediate restart

This shows a monitoring gap where Kubernetes detects failure late.

---

## Forensic Evidence Collection

### Kubernetes Events

kubectl get events -n forensic-lab --sort-by='.lastTimestamp'  
kubectl get events -n forensic-lab --watch  

Look for:

Exit Code 137 → OOMKilled

---

### Logs

kubectl logs <pod-name> -n forensic-lab --previous  

---

### Database Records

kubectl exec -it cassandra-0 -n forensic-lab -- cqlsh -e "SELECT * FROM forensic_lab.activity_log LIMIT 5;"

---

### Enabling Audit Logs for extra evidence

kubectl exec cassandra-0 -n forensic-lab -- nodetool enableauditlog --included-keyspaces forensic_lab  

---


## Summary

- Simulated DDoS-like workload  
- Observed memory exhaustion and pod restart  
- Captured forensic evidence before restart  
- Identified monitoring gap (Zombie State)

---

## Author

Prerit Bhandari  
