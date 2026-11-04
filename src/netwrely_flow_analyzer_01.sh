#!/bin/bash

set -e

PROJECT_ID=$(gcloud config get-value project 2>/dev/null)

echo "========================================="
echo " GCP Flow Analyzer Investigation Script"
echo "========================================="
echo "Project: $PROJECT_ID"
echo

echo "[1/6] Collecting VPC Flow Logs ..."

gcloud logging read \
'resource.type="gce_subnetwork"' \
--limit=2000 \
--format=json > flows.json

FLOW_COUNT=$(jq length flows.json)

echo "Collected $FLOW_COUNT flow records"
echo

echo "========================================="
echo " TOP SOURCE IPS"
echo "========================================="

jq -r '.[].jsonPayload.connection.src_ip // empty' flows.json \
| sort \
| uniq -c \
| sort -nr \
| head -10

echo
echo "========================================="
echo " TOP DESTINATION IPS"
echo "========================================="

jq -r '.[].jsonPayload.connection.dest_ip // empty' flows.json \
| sort \
| uniq -c \
| sort -nr \
| head -10

echo
echo "========================================="
echo " LARGEST TRANSFERS"
echo "========================================="

jq -r '
.[]
| select(.jsonPayload.bytes_sent != null)
| "\(.jsonPayload.bytes_sent) \(.jsonPayload.connection.src_ip) -> \(.jsonPayload.connection.dest_ip)"
' flows.json |
sort -nr |
head -20

echo
echo "========================================="
echo " TOP TALKER IP"
echo "========================================="

TOP_IP=$(jq -r '
.[].jsonPayload.connection.src_ip // empty
' flows.json |
sort |
uniq -c |
sort -nr |
head -1 |
awk '{print $2}')

echo "Suspicious Source IP: $TOP_IP"
echo

echo "========================================="
echo " VM MATCH"
echo "========================================="

gcloud compute instances list \
--filter="networkInterfaces.networkIP=$TOP_IP" \
--format="table(name,zone,status,networkInterfaces[0].networkIP)"

echo

VM_NAME=$(gcloud compute instances list \
--filter="networkInterfaces.networkIP=$TOP_IP" \
--format="value(name)" | head -1)

echo "========================================="
echo " DETAILED FLOWS FOR $TOP_IP"
echo "========================================="

jq -r --arg ip "$TOP_IP" '
.[]
| select(.jsonPayload.connection.src_ip==$ip)
| [
    .jsonPayload.connection.src_ip,
    .jsonPayload.connection.dest_ip,
    .jsonPayload.bytes_sent
  ]
| @tsv
' flows.json |
head -30

echo
echo "========================================="
echo " INVESTIGATION SUMMARY"
echo "========================================="
echo "Project           : $PROJECT_ID"
echo "Suspect Source IP : $TOP_IP"
echo "VM Name           : ${VM_NAME:-NOT FOUND}"
echo
echo "Investigation complete."
echo
