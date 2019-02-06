#!/bin/bash

S3_BUCKET=
INPUT_FILE=sam-template.yaml
OUTPUT_FILE=sam-template-output.yaml
STACK_NAME=example-website-authorizer

cd src
npm install --silent
npm run-script lint
npm test
npm prune --production
cd ..

aws cloudformation package --template-file $INPUT_FILE --output-template-file $OUTPUT_FILE --s3-bucket $S3_BUCKET --region us-east-1
aws cloudformation deploy --template-file $OUTPUT_FILE --stack-name $STACK_NAME --capabilities CAPABILITY_IAM --region us-east-1
