#!/bin/bash
kubectl delete svc couchdb -n ehsm-kms
kubectl delete svc ehsm-kms-service -n ehsm-kms
kubectl delete deployment ehsm-kms-deployment -n ehsm-kms
kubectl delete ds dkeycache-deamonset -n ehsm-kms
kubectl delete sts couchdb -n ehsm-kms
kubectl delete pvc couch-persistent-storage-couchdb-0 -n ehsm-kms
kubectl delete pv ehsm-pv-nfs -n ehsm-kms
kubectl delete cm ehsm-configmap -n ehsm-kms
kubectl delete secret ehsm-secret -n ehsm-kms