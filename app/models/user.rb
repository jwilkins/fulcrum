require 'net/ldap'

class User < ActiveRecord::Base
  # Include default devise modules. Others available are:
  # :token_authenticatable, :encryptable, :confirmable, :lockable, :timeoutable and :omniauthable
  devise :ldap_authenticatable, :registerable,
         :recoverable, :rememberable, :trackable, :validatable

  # Setup accessible (or protected) attributes for your model
  attr_accessible :email, :password, :password_confirmation, :remember_me

  # FIXME - DRY up, repeated in Story model
  JSON_ATTRIBUTES = ["id", "name", "initials", "email"]

  # Include default devise modules. Others available are:
  # :token_authenticatable, :confirmable, :lockable and :timeoutable
  devise :ldap_authenticatable, :registerable, 
         :recoverable, :rememberable, :trackable #, :validatable

  # Setup accessible (or protected) attributes for your model
  attr_accessible :email, :password, :password_confirmation, :remember_me,
                  :name, :initials #, :email_delivery, :email_acceptance, :email_rejection

  # Flag used to identify if the user was found or created from find_or_create
  attr_accessor :was_created

  has_and_belongs_to_many :projects, :uniq => true

  before_validation :set_random_password_if_blank, :set_reset_password_token

  validates :name, :presence => true
  validates :initials, :presence => true
#  before_save :get_ldap_email

  def to_s
    "#{name} (#{initials}) <#{email}>"
  end

  def after_initialize
    @config = YAML.load(ERB.new(File.read("#{Rails.root}/config/ldap.yml")).result)[Rails.env]
  end

  def set_random_password_if_blank
    if new_record? && self.password.blank? && self.password_confirmation.blank?
      self.password = self.password_confirmation = Digest::SHA1.hexdigest("--#{Time.now.to_s}--#{email}--")[0,6]
    end
  end

  def set_reset_password_token
    if new_record?
      self.reset_password_token = Devise.friendly_token
    end
  end

#  def get_ldap_email
#    self.email = Devise::LdapAdapter.get_ldap_param(self.username,"mail")
#  end

  def as_json(options = {})
    super(:only => JSON_ATTRIBUTES)
  end

  def ldap_auth(user, pass)
    ldap = initialize_ldap_con
    result = ldap.bind_as(
      :base => @config['base_dn'],
      :filter => "(#{@config['attributes']['id']}=#{user})",
      :password => pass
    )
    if result
      # fetch user DN
      get_user_dn user
      sync_ldap_with_db user
    end
    nil
  end

  private
  def initialize_ldap_con
    options = { :host => @config['host'],
                :port => @config['port'],
                :encryption => (@config['tls'] ? :simple_tls : nil),
                :auth => { 
                  :method => :simple,
                  :username => @config['ldap_user'],
                  :password => @config['ldap_password']
                }
              }
    Net::LDAP.new options
  end

  def get_user_dn(user)
    ldap = initialize_ldap_con
    login_filter = Net::LDAP::Filter.eq @config['attributes']['id'], "#{user}"
    object_filter = Net::LDAP::Filter.eq "objectClass", "*" 

    ldap.search :base => @config['base_dn'],
                :filter => object_filter & login_filter,
                :attributes => ['dn', @config['attributes']['first_name'], @config['attributes']['last_name'], @config['attributes']['mail']] do |entry|
      logger.debug "DN: #{entry.dn}"
      entry.each do |attr, values|
        values.each do |value|
          logger.debug "#{attr} = #{value}"
        end
      end
    end
  end

end
