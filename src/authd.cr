require "json"
require "jwt"
require "ipc"

require "baguette-crystal-base"
require "./user.cr"

# Allows get configuration from a provided file.
# See Baguette::Configuration::Base.get
class Baguette::Configuration
	class Auth < IPC
		include YAML::Serializable

		property login           : String? = nil
		property pass            : String? = nil
		property shared_key      : String  = "nico-nico-nii" # Default authd key, as per the specs. :eyes:
		property shared_key_file : String? = nil

		def initialize
		end
	end
end

# Requests and responses.
require "./exceptions"

# Requests and responses.
require "./network"

# Functions to request the authd server.
require "./libclient.cr"
