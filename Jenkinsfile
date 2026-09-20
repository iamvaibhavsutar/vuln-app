#!groovy
/*
 * Scripted pipeline (not declarative) — dynamic Kubernetes pod agent.
 *
 * One pod is created per build with one container per tool. Nothing is
 * pre-installed on any static Jenkins node; every stage runs in its own
 * container inside the same pod, sharing the workspace via the default
 * emptyDir volume the Kubernetes plugin mounts at $WORKSPACE.
 *
 * Toggle APP_MODULE between 'vuln-app' and 'fixed-app' to compare
 * SAST / SCA / DAST findings before and after the fix.
 *
 * Requires: Jenkins Kubernetes plugin, a ServiceAccount with permission to
 * create pods in the build namespace, and (for the deploy/DAST stages) a
 * ServiceAccount / RBAC allowing deployments in the 'security-demo' namespace.
 */

def APP_MODULE   = params.APP_MODULE ?: 'vuln-app'          // 'vuln-app' or 'fixed-app'
def IMAGE_NAME   = "vsutardevops/security-demo:${APP_MODULE}-${env.BUILD_NUMBER}"
def SCAN_NS      = 'security-demo'
def DEPLOY_URL   = "http://security-demo.${SCAN_NS}.svc.cluster.local:8080"

def podLabel = "sec-demo-${env.BUILD_NUMBER}"

podTemplate(
    label: podLabel,
    namespace: 'jenkins',
    serviceAccount: 'jenkins',
    containers: [
        containerTemplate(
            name: 'maven',
            image: 'maven:3.9-eclipse-temurin-17',
            command: 'sleep',
            args: 'infinity',
            resourceRequestCpu: '500m',
            resourceRequestMemory: '768Mi'
        ),
        containerTemplate(
            name: 'semgrep',
            image: 'returntocorp/semgrep:latest',
            command: 'sleep',
            args: 'infinity'
        ),
        containerTemplate(
            name: 'trivy',
            image: 'aquasec/trivy:latest',
            command: 'sleep',
            args: 'infinity'
        ),
        containerTemplate(
            name: 'kaniko',
            image: 'gcr.io/kaniko-project/executor:debug',
            command: 'sleep',
            args: '9999999',
            ttyEnabled: true
        ),
        containerTemplate(
            name: 'kubectl',
            image: 'bitnami/kubectl:latest',
            command: 'sleep',
            args: 'infinity'
        ),
        containerTemplate(
            name: 'zap',
            image: 'zaproxy/zap-stable:latest',
            command: 'sleep',
            args: 'infinity',
            runAsUser: '0'
        )
    ],
    volumes: [
        // Dockerfile is at APP_MODULE/Dockerfile relative to workspace root,
        // so Kaniko needs no extra secret mounts beyond the registry creds below.
        secretVolume(secretName: 'docker-registry-creds', mountPath: '/kaniko/.docker')
    ]
) {
    node(podLabel) {

        stage('Checkout') {
            checkout scm
        }

        stage('Build & Unit Test') {
            container('maven') {
                dir(APP_MODULE) {
                    sh 'mvn -B clean package'
                }
            }
        }

        stage('SAST - Semgrep') {
            container('semgrep') {
                dir(APP_MODULE) {
                    // Non-zero exit on findings would fail the build; capture the
                    // exit code instead so the report still gets archived, then
                    // decide pass/fail explicitly below.
                    def sastExit = sh(
                        script: '''
                            semgrep --config p/owasp-top-ten --config p/java \
                              --json --output semgrep-report.json . || true
                        ''',
                        returnStatus: true
                    )
                    echo "semgrep exit code: ${sastExit}"
                }
            }
            archiveArtifacts artifacts: "${APP_MODULE}/semgrep-report.json", allowEmptyArchive: true

            def findings = sh(
                script: "grep -o '\"check_id\"' ${APP_MODULE}/semgrep-report.json | wc -l || echo 0",
                returnStdout: true
            ).trim()
            echo "SAST findings: ${findings}"
            if (findings.toInteger() > 0 && APP_MODULE == 'vuln-app') {
                echo 'Findings expected on vuln-app — continuing pipeline for demo purposes.'
                // In a real pipeline you would likely: currentBuild.result = 'UNSTABLE'
            }
        }

        stage('SCA - Trivy (filesystem / dependency scan)') {
            container('trivy') {
                dir(APP_MODULE) {
                    sh '''
                        trivy fs \
                          --scanners vuln \
                          --severity CRITICAL,HIGH,MEDIUM \
                          --format json \
                          --output trivy-sca-report.json \
                          .
                        trivy fs \
                          --scanners vuln \
                          --severity CRITICAL,HIGH \
                          --exit-code 0 \
                          .
                    '''
                }
            }
            archiveArtifacts artifacts: "${APP_MODULE}/trivy-sca-report.json", allowEmptyArchive: true
        }

        stage('Package Image - Kaniko') {
            container('kaniko') {
                sh """
                    /kaniko/executor \
                      --context=dir://\$WORKSPACE/${APP_MODULE} \
                      --dockerfile=\$WORKSPACE/${APP_MODULE}/Dockerfile \
                      --destination=${IMAGE_NAME} \
                      --cache=true
                """
            }
        }

        stage('SCA - Trivy (image scan)') {
            container('trivy') {
                sh """
                    trivy image \
                      --severity CRITICAL,HIGH,MEDIUM \
                      --format json \
                      --output trivy-image-report.json \
                      ${IMAGE_NAME} || true
                """
            }
            archiveArtifacts artifacts: 'trivy-image-report.json', allowEmptyArchive: true
        }

        stage('Deploy to ephemeral scan environment') {
            container('kubectl') {
                sh """
                    kubectl create namespace ${SCAN_NS} --dry-run=client -o yaml | kubectl apply -f -
                    sed 's#__APP_IMAGE__#${IMAGE_NAME}#' k8s/deployment-template.yaml | kubectl apply -f -
                    kubectl -n ${SCAN_NS} rollout status deployment/security-demo --timeout=120s
                """
            }
        }

        stage('DAST - OWASP ZAP baseline scan') {
            container('zap') {
                def zapExit = sh(
                    script: """
                        mkdir -p /zap/wrk
                        zap-baseline.py \
                          -t ${DEPLOY_URL} \
                          -r zap-report.html \
                          -J zap-report.json \
                          -I || true
                        cp /zap/wrk/zap-report.* \$WORKSPACE/ || true
                    """,
                    returnStatus: true
                )
                echo "zap-baseline exit code: ${zapExit}"
            }
            archiveArtifacts artifacts: 'zap-report.*', allowEmptyArchive: true
        }

        stage('Cleanup ephemeral environment') {
            container('kubectl') {
                sh "kubectl -n ${SCAN_NS} delete deployment,service security-demo --ignore-not-found=true"
            }
        }
    }
}
