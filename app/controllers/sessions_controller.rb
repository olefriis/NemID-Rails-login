class SessionsController < ApplicationController
  protect_from_forgery :except => :create
  
  def new
    session[:challenge] = SecureRandom.hex(10)
  end
  
  def create
    result = org.openoces.securitypackage.SignHandler.base64Decode(request[:result]);
    if result == 'ok'
      handle_ok
    elsif result == 'cancel'
      redirect_to :cancelled
    else
      redirect_to :unknown_action
    end
  end
  
  def destroy
    session[:pid] = nil
    redirect_to :action => :new
  end
  
  def handle_ok
    certificate_and_status = get_certificate_and_status 
    if certificate_and_status.certificate_status() != org.openoces.ooapi.certificate.CertificateStatus.value_of('VALID')
      redirect_to :invalid_certificate
    elsif !is_poces(certificate_and_status)
      redirect_to :wrong_certificate_type
    else
      session[:pid] = certificate_and_status.certificate.pid
      redirect_to '/hemmelig'
    end
  end
  
  def get_certificate_and_status
    signature, challenge, service_provider = request[:signature], session[:challenge], 'www.nemid.nu'
    org.openoces.securitypackage.LogonHandler.validateAndExtractCertificateAndStatus(org.openoces.securitypackage.SignHandler.base64Decode(signature), challenge, service_provider);
  end
  
  def is_poces(certificate_and_status)
    certificate_and_status.certificate.kind_of? org.openoces.ooapi.certificate.PocesCertificate
  end
end
