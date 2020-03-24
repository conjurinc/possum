#!/usr/bin/env groovy

pipeline {
  agent { label 'executor-v2' }

  options {
    timestamps()
    buildDiscarder(logRotator(numToKeepStr: '30'))
    skipDefaultCheckout()  // see 'Checkout SCM' below, once perms are fixed this is no longer needed
  }

  triggers {
    cron(getDailyCronString())
  }

  stages {
    stage('Checkout SCM') {
      steps {
        checkout scm
        sh 'git fetch' // to pull the tags
      }
    }

    stage('Validate') {
      parallel {
        stage('Changelog') {
          steps { sh 'ci/parse-changelog' }
        }
      }
    }

    stage('Build Docker Image') {
      steps {
        sh './build.sh -j'
      }
    }

    stage('Scan Docker Image') {
      steps { 
        script {
          TAG = sh(returnStdout: true, script: 'echo $(< VERSION)-$(git rev-parse --short HEAD)')
        }
        scanAndReport("conjur:${TAG}", "CRITICAL") }
    }

    stage('Prepare For CodeClimate Coverage Report Submission'){
      steps {
        script {
          ccCoverage.dockerPrep()
          sh 'mkdir -p coverage'
        }
      }
    }

    stage('Run Tests') {
      parallel {
        stage('RSpec') {
          steps { sh 'ci/test rspec' }
        }
        stage('Authenticators Config') {
          steps { sh 'ci/test cucumber_authenticators_config' }
        }
        stage('Authenticators Status') {
          steps { sh 'ci/test cucumber_authenticators_status' }
        }
        stage('LDAP Authenticator') {
          steps { sh 'ci/test cucumber_authenticators_ldap' }
        }
        stage('OIDC Authenticator') {
          steps { sh 'ci/test cucumber_authenticators_oidc' }
        }
        // We have 2 stages for the Azure Authenticator tests. One is
        // responsible for allocating an Azure VM, from which we will get an
        // Azure access token for Conjur authentication. It sets the Azure VM IP
        // in the env and waits until the authn-azure tests are finished. We use
        // this mechanism as we need a live Azure VM for getting the Azure token
        // and we don't want to have a long running-machine deployed in Azure.
        stage('Azure Authenticator preparation - Allocate Azure Authenticator Instance') {
          steps {
            script {
              node('azure-authn') {
                env.AZURE_AUTHN_INSTANCE_IP = sh(script: 'curl icanhazip.com', returnStdout: true)
                env.KEEP_AZURE_AUTHN_INSTANCE = "true"
                while(env.KEEP_AZURE_AUTHN_INSTANCE == "true") {
                  sleep(time: 15, unit: "SECONDS")
                }
              }
            }
          }
        }
        stage('Azure Authenticator') {
          steps {
            script {
              while (!env.AZURE_AUTHN_INSTANCE_IP?.trim()) {
                sleep(time: 15, unit: "SECONDS")
              }
              sh(
                script: 'summon -f ci/authn-azure/secrets.yml ci/test cucumber_authenticators_azure',
              )
            }
          }
          post {
            always {
              script {
                env.KEEP_AZURE_AUTHN_INSTANCE = "false"
              }
            }
          }
        }
        stage('Policy') {
          steps { sh 'ci/test cucumber_policy' }
        }
        stage('API') {
          steps { sh 'ci/test cucumber_api' }
        }
        stage('Rotators') {
          steps { sh 'ci/test cucumber_rotators' }
        }
        stage('Kubernetes 1.7 in GKE') {
          steps { sh 'cd ci/authn-k8s && summon ./test.sh gke' }
        }
        stage('Audit') {
          steps { sh 'ci/test rspec_audit'}
        }
      }
      post {
        always {
          junit 'spec/reports/*.xml,spec/reports-audit/*.xml,cucumber/api/features/reports/**/*.xml,cucumber/policy/features/reports/**/*.xml,cucumber/authenticators/features/reports/**/*.xml'
          cucumber fileIncludePattern: '**/cucumber_results.json', sortingMethod: 'ALPHABETICAL'
        }
      }
    }

    stage('Submit Coverage Report'){
      steps{
        script {
          try {
            sh 'ci/submit-coverage'
          } finally {
            archiveArtifacts artifacts: "coverage/.resultset*.json", fingerprint: false
            archiveArtifacts artifacts: "ci/authn-k8s/output/simplecov-resultset-authnk8s-gke.json", fingerprint: false
            publishHTML([reportDir: 'coverage', reportFiles: 'index.html', reportName: 'Coverage Report', reportTitles: '', allowMissing: false, alwaysLinkToLastBuild: true, keepAll: true])
          }
        }
      }
    }

    stage('Push Docker image') {
      steps {
        sh './push-image.sh'
      }
    }

    stage('Build Debian package') {
      steps {
        sh './package.sh'

        archiveArtifacts artifacts: '*.deb', fingerprint: true
      }
    }

    stage('Publish Debian package'){
      steps {
        sh './publish.sh'
      }
    }
  }

  post {
    success {
      script {
        if (env.BRANCH_NAME == 'master') {
          build (job:'../cyberark--secrets-provider-for-k8s/master', wait: false)
        }
      }
    }
    always {
      cleanupAndNotify(currentBuild.currentResult, '#conjur-core', '', true)
    }
  }
}
