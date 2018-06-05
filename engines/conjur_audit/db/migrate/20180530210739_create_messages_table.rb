Sequel.migration do
  change do
    create_table :messages do
      Integer :facility, null: false
      Integer :severity, null: false
      timestamptz :timestamp, null: false
      String :hostname
      String :appname
      String :procid
      String :msgid
      jsonb :sdata
      String :message, null: false
    end
  end
end
