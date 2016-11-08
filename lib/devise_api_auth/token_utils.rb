module DeviseApiAuth
	module TokenUtils
		extend self
		require 'openssl'

		def generate_user_token(string, digester: Digest::SHA2)
			return if !string.is_a?(String) || string.blank?
			digester.hexdigest(string+DeviseApiAuth::Config.options[:user_salt])
		end

	  class SecureCredentials
	    def initialize(headers: nil, params: nil)
	      @headers = headers
	      @params = params
	    end

	    def get_header_credentials
	      decrypt(encrypted_header_credentials, iv: header_iv).symbolize_keys
	    end

	    def get_param_credentials
	      decrypt(encrypted_param_credentials, iv: params_iv).symbolize_keys
	    end

	    def header_iv
	      @headers&.fetch(config_options[:header_iv],nil)
	    end

	    def params_iv
	      @params&.fetch(config_options[:param_iv],nil)
	    end

	    def encrypted_header_credentials
	      @headers&.fetch(config_options[:header_credentials],nil)
	    end

	    def encrypted_param_credentials
	      @params&.fetch(config_options[:param_credentials],nil)
	    end

	    protected
	    def decrypt(encrypted, iv:)
	      decrypted = DeviseApiAuth::TokenUtils::Decryptor.new(iv).decrypt(encrypted)
	      JSON.parse decrypted
	    rescue StandardError => e
	      {}
	    end

	    def config_options
	    	DeviseApiAuth::Config.options
	  	end

	  end


	  private
	  class Crypt
	    # Subclasses must provide block to initializer to set encrypt or decrypt on the cipher

	    # Accepts iv as hex string
	    def initialize(iv)
	      @failed = false
	      @cipher = OpenSSL::Cipher::Cipher.new('aes-256-cbc')
	      yield @cipher # setting encrypt or decrypt to the cipher
	      @cipher.key = DeviseApiAuth::Config.options[:encryption_key]
	      @cipher.iv = [iv].pack('H*')
	    rescue StandardError => e
	      @failed = true
	    end

	    private
	    def crypt(to_crypt)
	      return if @failed
	      crypted = @cipher.update(to_crypt)
	      crypted << @cipher.final
	    rescue StandardError => e
	      nil
	    end
	  end

	  public
	  class Decryptor < Crypt
	    def initialize(iv)
	      super {|cipher| cipher.decrypt}
	    end

	    # Accepts an encrypted hex string and returns plain text
	    def decrypt(encrypted)
	      return if encrypted.blank?
	      crypt([encrypted].pack('H*'))
	    end

	  end

	  class Encryptor < Crypt
	    def initialize(iv)
	      super{|cipher| cipher.encrypt}
	    end

	    # Accepts string and returns encrypted hex string
	    def encrypt(encrypted)
	      crypt(encrypted)&.unpack('H*')&.first
	    end

	  end


	  class SimpleTokenMatcher
	    def initialize(strings: nil, token: nil, digester: nil)
	      @digester = digester || Digest::SHA2
	      @string = strings
	      if @string.is_a?(Array)
	      	@string = @string.include?(nil) ? nil : strings.join
	      end
	      @token = token
	      @_token = token_for @string
	    end
	    def match!
	      valid? && @_token == @token
	    end
	    def token_for(string)
	      return unless string.is_a?(String) && !string.blank?
	      @digester.hexdigest(string)
	    end
	    def valid?
	      !@_token.blank?
	    end
	  end

	  class DateTokenMatcher < SimpleTokenMatcher
	    # adds date and options hash that contains a verify_date bool and cutoff which is the amount of seconds to allow the date to be within
	    def initialize(strings: nil, token: nil, digester: nil, date: nil, **options)
	      @options = {verify_date: true, cutoff: 60 * 10}.merge(options)
	      self.date = date
	      super(strings: strings, token: token, digester: digester)
	    end
	    def match!
	      return false if verify_date? && !verify_date!
	      super
	    end
	    def valid?
	      return super if !verify_date?
	      verify_date! && super
	    end

	    private
	    def date=(d)
	      if d.is_a? String
	        @date = DateTime.parse(d)
	      elsif d.is_a? DateTime
	        @date = d
	      end
	    rescue ArgumentError
	      @date = nil
	    end
	    def verify_date!
	      return false if @date.nil?
	      a = cutoff.seconds.ago.to_datetime
	      b = cutoff.seconds.since.to_datetime
	      @date.between?(a,b)
	    end
	    def verify_date?
	      !!(@options[:verify_date])
	    end
	    def cutoff
	      [@options[:cutoff].to_i, 30].max
	    end

	  end

	end



end