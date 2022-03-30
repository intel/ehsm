#!/bin/bash
kubectl delete svc main -n dkeyserver
kubectl delete svc dkey-provisioning-service -n dkeyserver
kubectl delete deployment worker-deployment -n dkeyserver
kubectl delete sts main -n dkeyserver
kubectl delete cm dkeyserver-configmap -n dkeyserver