class ApplicationController < ActionController::API
  include Authenticates
  include ::ActionView::Layouts

  class Unauthorized < RuntimeError
  end

  class Forbidden < Exceptions::Forbidden
  end

  class RecordNotFound < Exceptions::RecordNotFound
  end

  class RecordExists < Exceptions::RecordExists
  end

  rescue_from Exceptions::RecordNotFound, with: :record_not_found
  rescue_from Exceptions::RecordExists, with: :record_exists
  rescue_from Exceptions::Forbidden, with: :forbidden
  rescue_from Unauthorized, with: :unauthorized
  rescue_from Sequel::ValidationFailed, with: :validation_failed
  rescue_from Sequel::NoMatchingRow, with: :no_matching_row
  rescue_from Sequel::ForeignKeyConstraintViolation, with: :foreign_key_constraint_violation
  rescue_from Conjur::PolicyParser::Invalid, with: :policy_invalid
  rescue_from ArgumentError, with: :argument_error

  around_action :run_with_transaction

  private

  # Wrap the request in a transaction.
  def run_with_transaction
    Sequel::Model.db.transaction do
      yield
    end
  end

  def record_not_found e
    logger.debug "#{e}\n#{e.backtrace.join "\n"}" if e.backtrace
    render json: {
      error: {
        code: "not_found",
        message: e.message,
        target: e.kind,
        details: {
          code: "not_found",
          target: "id",
          message: e.id
        }
      }
    }, status: :not_found
  end

  def no_matching_row e
    logger.debug "#{e}\n#{e.backtrace.join "\n"}"
    target = e.dataset.model.table_name.to_s.underscore rescue nil
    render json: {
      error: {
        code: "not_found",
        target: target,
        message: e.message
      }.compact
    }, status: :not_found
  end

  def foreign_key_constraint_violation e
    logger.debug "#{e}\n#{e.backtrace.join "\n"}"

    # check if this is a violation of role_memberships_member_id_fkey
    # or role_memberships_role_id_fkey
    # sample exceptions:
    # PG::ForeignKeyViolation: ERROR:  insert or update on table "role_memberships" violates foreign key constraint "role_memberships_member_id_fkey"
    # DETAIL:  Key (member_id)=(cucumber:group:security-admin) is not present in table "roles".
    # or
    # PG::ForeignKeyViolation: ERROR:  insert or update on table "role_memberships" violates foreign key constraint "role_memberships_role_id_fkey"
    # DETAIL:  Key (role_id)=(cucumber:group:developers) is not present in table "roles".
    if e.message.index(/role_memberships_member_id_fkey/) ||
      e.message.index(/role_memberships_role_id_fkey/)

      key_string = ''
      e.message.split(" ").map do |text|
        if text["(member_id)"] || text["(role_id)"]
          key_string = text 
          break 
        end 
      end

      # the member ID is inside the second set of parentheses of the key_string
      key_index = key_string.index(/\(/, 1) + 1
      key = key_string[ key_index, key_string.length - key_index - 1 ]

      exc = Exceptions::RecordNotFound.new key, message: "Role #{key} does not exist"
      record_not_found exc
    else
      # if this isn't a case we're handling yet, let the exception proceed
      raise e
    end
  end

  def validation_failed e
    logger.debug "#{e}\n#{e.backtrace.join "\n"}"
    message = e.errors.map do |field, messages|
      messages.map do |message|
        [ field, message ].join(' ')
      end
    end.flatten.join(',')

    details = e.errors.map do |field, messages|
      messages.map do |message|
        {
          code: error_code_of_exception_class(e.class),
          target: field,
          message: message
        }
      end
    end.flatten

    render json: {
      error: {
        code: error_code_of_exception_class(e.class),
        message: message,
        details: details
      }
    }, status: :unprocessable_entity
  end

  def policy_invalid e
    logger.debug "#{e}\n#{e.backtrace.join "\n"}"
    render json: {
      error: {
        code: "policy_invalid",
        message: e.message,
        innererror: {
          code: "policy_invalid",
          filename: e.filename,
          line: e.mark.line,
          column: e.mark.column
        }
      }
    }, status: :unprocessable_entity
  end

  def argument_error  e
    logger.debug "#{e}\n#{e.backtrace.join "\n"}"
    render json: {
      error: {
        code: error_code_of_exception_class(e.class),
        message: e.message
      }
    }, status: :unprocessable_entity
  end

  def record_exists e
    logger.debug "#{e}\n#{e.backtrace.join "\n"}"
    render json: {
      error: {
        code: "conflict",
        message: e.message,
        target: e.kind,
        details: {
          code: "conflict",
          target: "id",
          message: e.id
        }
      }
    }, status: :conflict
  end

  def forbidden e
    logger.debug "#{e}\n#{e.backtrace.join "\n"}"
    head :forbidden
  end

  def unauthorized e
    logger.debug "#{e}\n#{e.backtrace.join "\n"}"
    head :unauthorized
  end

  # Gets the value of the :account parameter.
  def account
    @account ||= params[:account]
  end

  def error_code_of_exception_class cls
    cls.to_s.underscore.split('/')[-1]
  end
end
