require File.expand_path('../lib/devise_api_auth/version', __FILE__)
Gem::Specification.new do |s|
  s.name        = 'devise_api_auth'
  s.version     = DeviseApiAuth::VERSION
  s.date        = '2016-11-06'
  s.summary     = "Devise API Authentication"
  s.description = "This gem provides functionality to authenticate mobile apps in addition to web apps using devise."
  s.authors     = ["Jose Castellanos"]
  s.email       = 'nextgenappsllc@gmail.com'
  s.files       = ["lib/devise_api_auth.rb","lib/devise_api_auth/api_token_authentication.rb","lib/devise_api_auth/config.rb","lib/devise_api_auth/date_csrf.rb","lib/devise_api_auth/token_utils.rb"]
  s.require_paths = ["lib"]
  s.homepage    = 'http://rubygems.org/gems/devise_api_auth'
  s.license     = 'MIT'
  s.required_ruby_version = '~> 2.3'
  s.add_dependency 'rails'
  s.add_dependency 'devise'
end