#!/bin/bash
set -e

echo "=============================================="
echo "    Sentrix WAF - GCP Production Deployment   "
echo "=============================================="

if ! command -v gcloud &> /dev/null; then
    echo "❌ Error: Google Cloud CLI (gcloud) is not installed."
    exit 1
fi

if ! command -v kubectl &> /dev/null; then
    echo "❌ Error: Kubernetes CLI (kubectl) is not installed."
    exit 1
fi

echo "Authenticate with Google Cloud if you haven't already."
echo "Running 'gcloud auth login'..."
gcloud auth login

read -p "Enter your target GCP Project ID: " PROJECT_ID

if [ -z "$PROJECT_ID" ]; then
    echo "Project ID cannot be empty."
    exit 1
fi

gcloud config set project "$PROJECT_ID"
gcloud services enable compute.googleapis.com container.googleapis.com artifactregistry.googleapis.com cloudbuild.googleapis.com

echo "Setting up Artifact Registry 'sentrix-repo'..."
if ! gcloud artifacts repositories describe sentrix-repo --location=us-central1 &> /dev/null; then
    gcloud artifacts repositories create sentrix-repo --repository-format=docker --location=us-central1
else
    echo "Repository already exists."
fi

gcloud auth configure-docker us-central1-docker.pkg.dev --quiet

IMAGE_BASE="us-central1-docker.pkg.dev/$PROJECT_ID/sentrix-repo"

echo "Updating kubernetes manifests with your Project ID..."
if [[ "$OSTYPE" == "darwin"* ]]; then
  sed -i '' "s|gcr.io/PROJECT|$IMAGE_BASE|g" k8s/waf-deployment.yaml
  sed -i '' "s|gcr.io/PROJECT|$IMAGE_BASE|g" k8s/demo-deployment.yaml
  sed -i '' "s|gcr.io/PROJECT|$IMAGE_BASE|g" k8s/dashboard-deployment.yaml
else
  sed -i "s|gcr.io/PROJECT|$IMAGE_BASE|g" k8s/waf-deployment.yaml
  sed -i "s|gcr.io/PROJECT|$IMAGE_BASE|g" k8s/demo-deployment.yaml
  sed -i "s|gcr.io/PROJECT|$IMAGE_BASE|g" k8s/dashboard-deployment.yaml
fi

echo "Building WAF API Image..."
docker build -f Dockerfile.waf -t "$IMAGE_BASE/waf:latest" .
docker push "$IMAGE_BASE/waf:latest"

echo "Building Demo App Image..."
docker build -f Dockerfile.demo -t "$IMAGE_BASE/demo-app:latest" .
docker push "$IMAGE_BASE/demo-app:latest"

echo "Building Dashboard Image..."
docker build -f Dockerfile.dashboard -t "$IMAGE_BASE/dashboard:latest" .
docker push "$IMAGE_BASE/dashboard:latest"

echo "GKE Cluster Provisioning 'sentrix-cluster'..."
if ! gcloud container clusters describe sentrix-cluster --zone us-central1-a &> /dev/null; then
    gcloud container clusters create sentrix-cluster \
      --zone us-central1-a \
      --num-nodes 3 \
      --machine-type e2-standard-4 \
      --enable-autoscaling --min-nodes 3 --max-nodes 6
fi

gcloud container clusters get-credentials sentrix-cluster --zone us-central1-a

echo "Deploying Kubernetes Manifests..."
kubectl apply -f k8s/namespace.yaml
kubectl apply -f k8s/demo-deployment.yaml
kubectl apply -f k8s/waf-deployment.yaml
kubectl apply -f k8s/dashboard-deployment.yaml

echo "🎉 Deployment initiated successfully!"
echo "Run the following commands to monitor the status:"
echo "  kubectl get pods -n sentrix-waf"
echo "  kubectl get svc -n sentrix-waf"
