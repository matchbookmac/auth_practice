class User < ActiveRecord::Base

  attr_accessor :password
  validates_confirmation_of :password
  validates :email, presence: true
  validates :password, presence: true
  before_save :encrypt_password

  def encrypt_password
# binding.pry
    self.password_salt = BCrypt::Engine.generate_salt
    self.password_hash = BCrypt::Engine.hash_secret(password, password_salt)
  end

  def self.authenticate(email, password)

  end
end
