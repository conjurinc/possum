require 'spec_helper'

describe Account, :type => :model do
  let(:account_name) { "account-crud-rspec" }

  def create_account
    Account.create account_name
  end

  describe "account creation" do
    describe "when the account does not exist" do
      it "succeeds" do
        create_account

        expect(Slosilo["authn:#{account_name}"]).to be
        admin = Role["#{account_name}:user:admin"]
        expect(admin).to be
        expect(admin.credentials).to be
      end
    end

    describe "when the account exists" do
      it "refuses" do
        create_account

        expect { Account.create account_name }.to raise_error(%Q(Account "account-crud-rspec" already exists))
      end
    end
  end

  describe "account listing" do
    before {
      create_account
    }
    it "includes the new account" do
      expect(Account.list).to include(account_name)
    end

    it "does not include the special account !" do
      expect(Account.list).to_not include("!")
    end
  end

  describe "account deletion" do
    describe "when the account does not exist" do
      it "is not found" do
        expect { Account.new(account_name).delete }.to raise_error(Exceptions::RecordNotFound)
      end
    end

    describe "when the account exists" do
      it "deletes it" do
        create_account
        Account.new(account_name).delete 

        expect(Slosilo["authn:#{account_name}"]).to_not be
        expect(Role["#{account_name}:user:admin"]).to_not be
      end
    end
  end
end
