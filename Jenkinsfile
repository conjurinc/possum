#!/usr/bin/env groovy

pipeline {
  agent { label 'executor-v2' }

  options {
    timestamps()
    buildDiscarder(logRotator(numToKeepStr: '30'))
    timeout(time: 1, unit: 'HOURS')
  }

  triggers {
    parameterizedCron(getDailyCronString("%NIGHTLY=true"))
  }

  parameters {
    booleanParam(name: 'NIGHTLY', defaultValue: false, description: 'Run tests on all agents and environment including: FIPS')
  }

  stages {
    stage('Fetch tags') {
      steps {
        withCredentials(
          [usernameColonPassword(credentialsId: 'conjur-jenkins-api', variable: 'GITCREDS')]
        ) {
          sh '''
            git fetch --tags `git remote get-url origin | sed -e "s|https://|https://$GITCREDS@|"`
            git tag # just print them out to make sure, can remove when this is robust
          '''
        }
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
        sh './build.sh --jenkins'
      }
    }

    stage('Scan Docker Image') {
      parallel {
        stage("Scan Docker Image for fixable issues") {
          steps {
            script {
              TAG = sh(returnStdout: true, script: 'echo $(< VERSION)-$(git rev-parse --short=8 HEAD)')
            }
            scanAndReport("conjur:${TAG}", "HIGH", false)
          }
        }
        stage("Scan Docker image for total issues") {
          steps {
            script {
              TAG = sh(returnStdout: true, script: 'echo $(< VERSION)-$(git rev-parse --short=8 HEAD)')
            }
            scanAndReport("conjur:${TAG}", "NONE", true)
          }
        }
      }
    }

    stage('Prepare For CodeClimate Coverage Report Submission'){
      steps {
        catchError(buildResult: 'SUCCESS', stageResult: 'FAILURE') {
          script {
            ccCoverage.dockerPrep()
            sh 'mkdir -p coverage'
            env.CODE_CLIMATE_PREPARED = "true"
          }
        }
      }
    }

    stage('Run environment tests in parallel') {
      parallel {
          stage('EE FIPS agent tests') {
            agent { label 'executor-v2-rhel-ee' }
            when {
                beforeAgent true
                expression { params.NIGHTLY }
            }
            steps {
              script {
                 parallel([
                    "RSpec - ${env.STAGE_NAME}": {
                      sh 'ci/test rspec'
                    },
                    "Authenticators Config - ${env.STAGE_NAME}": {
                      sh 'ci/test cucumber_authenticators_config'
                    },
                    "Authenticators Status - ${env.STAGE_NAME}": {
                      sh 'ci/test cucumber_authenticators_status'
                    },
                    "LDAP Authenticator - ${env.STAGE_NAME}": {
                      sh 'ci/test cucumber_authenticators_ldap'
                    },
                    "OIDC Authenticator - ${env.STAGE_NAME}": {
                      sh 'ci/test cucumber_authenticators_oidc'
                    },
                    "Policy - ${env.STAGE_NAME}": {
                      sh 'ci/test cucumber_policy'
                    },
                    "API - ${env.STAGE_NAME}": {
                      sh 'ci/test cucumber_api'
                    },
                    "Rotators - ${env.STAGE_NAME}": {
                      sh 'ci/test rspec'
                    },
                    "Kubernetes 1.7 in GKE - ${env.STAGE_NAME}": {
                      sh 'cd ci/authn-k8s && summon ./test.sh gke'
                    },
                    "Audit - ${env.STAGE_NAME}": {
                      sh 'ci/test rspec_audit'
                    }
                 ])
              }
              stash name: 'testResultEE', includes: "cucumber/*/*.*,container_logs/*/*,spec/reports/*.xml,spec/reports-audit/*.xml,cucumber/*/features/reports/**/*.xml"
            }
          } // EE FIPS agent tests

          stage('Standard agent tests') {
            steps {
              script {
                 parallel([
                    "RSpec - ${env.STAGE_NAME}": {
                      sh 'ci/test rspec'
                    },
                    "Authenticators Config - ${env.STAGE_NAME}": {
                      sh 'ci/test cucumber_authenticators_config'
                    },
                    "Authenticators Status - ${env.STAGE_NAME}": {
                      sh 'ci/test cucumber_authenticators_status'
                    },
                    "LDAP Authenticator - ${env.STAGE_NAME}": {
                      sh 'ci/test cucumber_authenticators_ldap'
                    },
                    "OIDC Authenticator - ${env.STAGE_NAME}": {
                      sh 'ci/test cucumber_authenticators_oidc'
                    },
                    "Policy - ${env.STAGE_NAME}": {
                      sh 'ci/test cucumber_policy'
                    },
                    "API - ${env.STAGE_NAME}": {
                      sh 'ci/test cucumber_api'
                    },
                    "Rotators - ${env.STAGE_NAME}": {
                      sh 'ci/test rspec'
                    },
                    "Kubernetes 1.7 in GKE - ${env.STAGE_NAME}": {
                      sh 'cd ci/authn-k8s && summon ./test.sh gke'
                    },
                    "Audit - ${env.STAGE_NAME}": {
                      sh 'ci/test rspec_audit'
                    }
                 ])
             }
            }
          } // Standard agent tests

        stage('Azure Authenticator') {
          steps {
            script {
              node('azure-linux') {
                // get `ci/authn-azure/get_system_assigned_identity.sh` from scm
                checkout scm
                env.AZURE_AUTHN_INSTANCE_IP = sh(script: 'curl icanhazip.com', returnStdout: true).trim()
                env.SYSTEM_ASSIGNED_IDENTITY = sh(script: 'ci/authn-azure/get_system_assigned_identity.sh', returnStdout: true).trim()

                sh('summon -f ci/authn-azure/secrets.yml ci/test cucumber_authenticators_azure')
              }
            }
          }
        }
        // We have 2 stages for GCP Authenticator tests. The first one runs inside
        // a GCE instance and retrieves all the tokens that will be used in the tests.
        // It then stashes the tokens, which are unstashed in the stage that runs the
        // GCP Authenticator tests using the tokens.
        // This way we can have a light-weight GCE instance that has no need for conjurops
        // or git identities and is not open for SSH
        stage('GCP Authenticator preparation - Allocate GCE Instance') {
          steps {
            script {
              node('executor-v2-gcp-small') {
                sh '''
                  retrieve_token() {
                    local token_format="$1"
                    local audience="$2"

                    curl \
                      -s \
                      -H 'Metadata-Flavor: Google' \
                      "http://metadata/computeMetadata/v1/instance/service-accounts/default/identity?format=${token_format}&audience=${audience}"
                  }

                  echo "$(retrieve_token "full" "conjur/cucumber/host/test-app")" > "gcp_token_valid"
                  echo "$(retrieve_token "full" "conjur/cucumber/host/non-existing")" > "gcp_token_non_existing_host"
                  echo "$(retrieve_token "full" "conjur/cucumber/host/non-rooted/test-app")" > "gcp_token_non_rooted_host"
                  echo "$(retrieve_token "full" "conjur/cucumber/test-app")" > "gcp_token_user"
                  echo "$(retrieve_token "full" "conjur/non-existing/host/test-app")" > "gcp_token_non_existing_account"
                  echo "$(retrieve_token "full" "invalid_audience")" > "gcp_token_invalid_audience"
                  echo "$(retrieve_token "standard" "conjur/cucumber/host/test-app")" > "gcp_token_standard_format"
                '''

                stash name: 'authnGcpTokens', includes: 'gcp_token_valid,gcp_token_invalid_audience,gcp_token_standard_format,gcp_token_user,gcp_token_non_existing_host,gcp_token_non_existing_account,gcp_token_non_rooted_host', allowEmpty:false
                env.GCP_TOKENS_FETCHED = "true"
              }
            }
          }
        }
        stage('GCP Authenticator') {
          steps {
            timeout(time: 10, unit: 'MINUTES') {
              waitUntil {
                script {
                  return (env.GCP_TOKENS_FETCHED == "true")
                }
              }
            }
            script {
              dir('ci/authn-gcp/tokens') {
                unstash 'authnGcpTokens'
              }

              sh 'ci/test cucumber_authenticators_gcp'
            }
          }
        }
      }
    }

    stage('Submit Coverage Report'){
      when {
        expression {
          env.CODE_CLIMATE_PREPARED == "true"
        }
      }
      steps{
        sh 'ci/submit-coverage'
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
      script {
          env.nightly_msg = ""
          if (params.NIGHTLY) {
            env.nightly_msg = "nightly"
            dir('ee-test'){
                 unstash 'testResultEE'
            }
            archiveArtifacts artifacts: "ee-test/cucumber/*/*.*", fingerprint: false, allowEmptyArchive: true
            archiveArtifacts artifacts: "ee-test/container_logs/*/*", fingerprint: false, allowEmptyArchive: true

            publishHTML([reportDir: 'ee-test/cucumber', reportFiles: 'api/cucumber_results.html, 	authenticators_config/cucumber_results.html, \
                                     authenticators_azure/cucumber_results.html, authenticators_ldap/cucumber_results.html, \
                                     authenticators_oidc/cucumber_results.html, authenticators_status/cucumber_results.html,\
                                     policy/cucumber_results.html , rotators/cucumber_results.html',\
                                     reportName: 'EE Integration reports', reportTitles: '', allowMissing: false, alwaysLinkToLastBuild: true, keepAll: true])

          }
      }
      archiveArtifacts artifacts: "container_logs/*/*", fingerprint: false, allowEmptyArchive: true
      archiveArtifacts artifacts: "coverage/.resultset*.json", fingerprint: false, allowEmptyArchive: true
      archiveArtifacts artifacts: "ci/authn-k8s/output/simplecov-resultset-authnk8s-gke.json", fingerprint: false, allowEmptyArchive: true
      archiveArtifacts artifacts: "cucumber/*/*.*", fingerprint: false, allowEmptyArchive: true

      publishHTML([reportDir: 'cucumber', reportFiles: 'api/cucumber_results.html, 	authenticators_config/cucumber_results.html, \
                               authenticators_azure/cucumber_results.html, authenticators_ldap/cucumber_results.html, \
                               authenticators_oidc/cucumber_results.html, authenticators_status/cucumber_results.html,\
                               policy/cucumber_results.html , rotators/cucumber_results.html',\
                               reportName: 'Integration reports', reportTitles: '', allowMissing: false, alwaysLinkToLastBuild: true, keepAll: true])


      publishHTML([reportDir: 'coverage', reportFiles: 'index.html', reportName: 'Coverage Report', reportTitles: '', allowMissing: false, alwaysLinkToLastBuild: true, keepAll: true])
      junit 'spec/reports/*.xml,spec/reports-audit/*.xml,cucumber/*/features/reports/**/*.xml,ee-test/spec/reports/*.xml,ee-test/spec/reports-audit/*.xml,ee-test/cucumber/*/features/reports/**/*.xml'
      cucumber fileIncludePattern: '**/cucumber_results.json', sortingMethod: 'ALPHABETICAL'


      cleanupAndNotify(currentBuild.currentResult, '#conjur-core', "${env.nightly_msg}", true)
    }
  }
}
