class SecretPagesController < ApplicationController
  def index
    check_login
  end
  
  private
  def check_login
    unless session[:pid]
      redirect_to :controller => :sessions, :action => :new
    end
  end
end
