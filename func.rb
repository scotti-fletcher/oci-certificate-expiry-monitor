require 'fdk'
require 'oci/common'
require 'oci/auth/auth'
require 'oci/identity/identity'
require 'oci/email/email'
require 'oci/secrets/secrets'
require 'oci/resource_search/resource_search'
require 'oci/functions/functions'
require 'oci/loggingingestion/loggingingestion'
require 'oci/certificates/certificates'
require 'pony'

OCI_TENANCY_OCID = ENV['OCI_TENANCY_OCID'].strip
OCI_LOG_OCID = ENV['OCI_LOG_OCID'].strip
EXPIRY_WARNING_DAYS = ENV['EXPIRY_WARNING_DAYS'].to_i
EXPIRY_CRITICAL_DAYS = ENV['EXPIRY_CRITICAL_DAYS'].to_i
CERTIFICATE_ADMIN_EMAILS = ENV['CERTIFICATE_ADMIN_EMAILS'].split(',').map { |e| e.strip }
EMAIL_DOMAIN = ENV['EMAIL_DOMAIN'].strip
SMTP_ENDPOINT = ENV['SMTP_ENDPOINT'].strip
VAULT_OCID = ENV['VAULT_OCID'].strip
REGION = ENV['OCI_RESOURCE_PRINCIPAL_REGION']
OCI_SECRET_SMTP_USERNAME = ENV['OCI_SECRET_SMTP_USERNAME'].strip
OCI_SECRET_SMTP_PASSWORD = ENV['OCI_SECRET_SMTP_PASSWORD'].strip

#returns the OCI principal signer, authn & authz of the function in the tenancy
def get_signer
    session_token = ENV['OCI_RESOURCE_PRINCIPAL_RPST']
    private_key = ENV['OCI_RESOURCE_PRINCIPAL_PRIVATE_PEM']
    private_key_passphrase = ENV['OCI_RESOURCE_PRINCIPAL_PRIVATE_PEM_PASSPHRASE']
    region = ENV['OCI_RESOURCE_PRINCIPAL_REGION']
    return OCI::Auth::Signers::EphemeralResourcePrincipalsSigner.new(
      session_token: session_token,
      private_key: private_key,
      private_key_passphrase: private_key_passphrase,
      region: region
    )
end

def log_action(certificate, error_type, message)
  log_time = Time.now.utc.strftime('%Y-%m-%dT%H:%M:%S.000Z')
  loggingingestion_client = OCI::Loggingingestion::LoggingClient.new(signer: get_signer, region: REGION)
  loggingingestion_client.put_logs(
    OCI_LOG_OCID,
    OCI::Loggingingestion::Models::PutLogsDetails.new(
      specversion: '1.0',
      log_entry_batches: [
        OCI::Loggingingestion::Models::LogEntryBatch.new(
          entries: [
            OCI::Loggingingestion::Models::LogEntry.new(
              data: { log_time: log_time, certificate_ocid: certificate.certificate_id, message: message}.to_json,
              id: "ocid1.certificatcher.oc1..#{SecureRandom.uuid}",
              time: log_time
            )
          ],
          source: 'certificatcher',
          type: "watchdog-#{error_type}",
          defaultlogentrytime: log_time,
          subject: 'Certificatcher Activity'
        )
      ]
    )
  )
end

def get_subscribed_regions
  identity_client = OCI::Identity::IdentityClient.new(signer: get_signer)
  results = identity_client.list_region_subscriptions(OCI_TENANCY_OCID)
  results.data.select { |r| r.status == 'READY' }.collect { |r| r.region_name }
end

def get_region_certs(region)
  resource_search_client = OCI::ResourceSearch::ResourceSearchClient.new(signer: get_signer, region: region)
  resource_search_client.search_resources(
    OCI::ResourceSearch::Models::StructuredSearchDetails.new(
      type: 'Structured',
      matching_context_type: 'NONE',
      query: "query certificate resources where lifecycleState = 'ACTIVE'"
    )).data.items
end

def check_certificate(ocid, region)
    certificates_client = OCI::Certificates::CertificatesClient.new(signer: get_signer, region: region)
    certificate = certificates_client.get_certificate_bundle(ocid, stage: 'LATEST').data
    if Date.today.next_day(EXPIRY_CRITICAL_DAYS) >= certificate.validity.time_of_validity_not_after
      send_email(CERTIFICATE_ADMIN_EMAILS, 'OCI Certificate Expiry - Critical', "#{certificate.certificate_name} in region #{region} will expire in #{certificate.validity.time_of_validity_not_after.mjd - DateTime.now.mjd} days")
      log_action(certificate, "critical", "#{certificate.certificate_name} in region #{region} will expire in #{certificate.validity.time_of_validity_not_after.mjd - DateTime.now.mjd} days")
    elsif Date.today.next_day(EXPIRY_WARNING_DAYS) >= certificate.validity.time_of_validity_not_after
      send_email(CERTIFICATE_ADMIN_EMAILS, 'OCI Certificate Expiry - Warning', "#{certificate.certificate_name} in region #{region} will expire in #{certificate.validity.time_of_validity_not_after.mjd - DateTime.now.mjd} days")
      log_action(certificate, "warning", "#{certificate.certificate_name} in region #{region} will expire in #{certificate.validity.time_of_validity_not_after.mjd - DateTime.now.mjd} days")
    else
      log_action(certificate, "info", "#{certificate.certificate_name} in region #{region} will expire in #{certificate.validity.time_of_validity_not_after.mjd - DateTime.now.mjd} days")
    end
end

def get_secret_value(secret_name)
  secret_client = OCI::Secrets::SecretsClient.new(signer: get_signer, region: REGION)
  acc_key_secret = secret_client.get_secret_bundle_by_name(secret_name, VAULT_OCID, stage: 'CURRENT').data
  Base64.decode64(acc_key_secret.secret_bundle_content.content)
end

def send_email(to, subject, body)
  Pony.mail({
              to: to,
              from: "certificatcher@#{EMAIL_DOMAIN}",
              reply_to: "noreply@#{EMAIL_DOMAIN}",
              via: :smtp,
              via_options: {
                address: SMTP_ENDPOINT,
                port: '587',
                user_name: get_secret_value(OCI_SECRET_SMTP_USERNAME),
                password: get_secret_value(OCI_SECRET_SMTP_PASSWORD),
                authentication: :plain, # :plain, :login, :cram_md5, no auth by default
                domain: EMAIL_DOMAIN # the HELO domain provided by the client to the server
              },
              subject: subject,
              body: body
            })
end

def check_certs(context:, input:)
  FDK.log(entry: "Certificatcher watchdog started #{Time.now.strftime('%Y-%m-%d %H:%M')}")
  get_subscribed_regions.each do |region|
    get_region_certs(region).each do |cert|
      check_certificate(cert.identifier, region)
    end
  end
  FDK.log(entry: "Certificatcher watchdog checks completed #{Time.now.strftime('%Y-%m-%d %H:%M')}")
  "Certificatcher watchdog checks completed #{Time.now.strftime('%Y-%m-%d %H:%M')}"
end

FDK.handle(target: :check_certs)