#!/bin/bash
export QUAY_REGISTRY="quay.io"
export QPC_NAMESPACE="discovery"
export QPC_PULL_SECRET="discovery-pull-secret"
export QPC_PULL_SECRET_JSON="/tmp/qpc_pull_secret_$$.json"


if [ $# -ne 3 ]
then
  echo "Usage: create_pull_secret.sh <quay_user> <quay_password> <quay_email>"
  exit 1
fi

export QUAY_REGISTRY_USER="${1}"
export QUAY_REGISTRY_PASSWORD="${2}"
export QUAY_REGISTRY_EMAIL="${3}"

CONFIG_JSON=`cat - <<!END!
{
  "auths" :
    {
      "${QUAY_REGISTRY}" : {
        "username" : "${QUAY_REGISTRY_USER}",
        "password" : "${QUAY_REGISTRY_PASSWORD}",
        "email"    : "${QUAY_REGISTRY_EMAIL}"
      }
    }
}
!END!
`
echo "Creating the Discovery pull secret ${QPC_PULL_SECRET} ..."

echo ${CONFIG_JSON} > ${QPC_PULL_SECRET_JSON}

if [ "$(oc get secrets -n ${QPC_NAMESPACE} | grep ${QPC_PULL_SECRET})" == "" ]
then
  oc create secret generic ${QPC_PULL_SECRET} --from-file=.dockerconfigjson=${QPC_PULL_SECRET_JSON} \
    --type=kubernetes.io/dockerconfigjson -n ${QPC_NAMESPACE}
else
  oc create secret generic ${QPC_PULL_SECRET} --from-file=.dockerconfigjson=${QPC_PULL_SECRET_JSON} \
    --type=kubernetes.io/dockerconfigjson -n ${QPC_NAMESPACE} --dry-run=client -o yaml | oc replace -n ${QPC_NAMESPACE} -f -
fi

# Zap the pull secret config json
rm -f ${QPC_PULL_SECRET_JSON}

for sa in "default" "deployer"
do
  oc get sa/${sa} >/dev/null 2>&1
  if [ $? -eq 0 ]
  then
    echo "Add ${QPC_PULL_SECRET} to the ${sa} service_account ..."
    oc secrets link ${sa}  ${QPC_PULL_SECRET} --for=pull
  fi
done

