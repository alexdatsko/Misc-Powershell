function Create-SQLite {
  param (
    [string]$DB = $script:SQLiteDB,
    [string]$Table = "QIDsFixed",
    [string]$Key
  )

  [System.Reflection.Assembly]::LoadWithPartialName("System.Data.SQLite")
  $connString = "Data Source=$DB" 

  $conn = New-Object System.Data.SQLite.SQLiteConnection -ArgumentList $connString
  $conn.Open()
  $sql = "CREATE TABLE [IF NOT EXISTS] [schema_name].$($Table) (
	qid INTEGER PRIMARY KEY,
  date_fixed TEXT
) WITHOUT ROWID;"
  $cmd = New-Object System.Data.SQLite.SQLiteCommand -ArgumentList $sql, $conn
  $cmd.ExecuteNonQuery()
  $conn.Close()
}

function Get-SQLite {
  param (
    [string]$DB = $script:SQLiteDB,
    [string]$Table,
    [string]$Key = "*"
  )

  [System.Reflection.Assembly]::LoadWithPartialName("System.Data.SQLite")
  $connString = "Data Source=$DB" 

  $conn = New-Object System.Data.SQLite.SQLiteConnection -ArgumentList $connString
  $conn.Open()
  $sql = "SELECT $Key FROM $Table"
  $cmd = New-Object System.Data.SQLite.SQLiteCommand -ArgumentList $sql, $conn
  $reader = $cmd.ExecuteReader()
  while ($reader.Read()) {
      # Access data using $reader["column_name"]
      return $reader[$Key]
  }
  $conn.Close()
}

function Set-SQLite {
  param (
    [string]$DB = $script:SQLiteDB,
    [string]$Table,
    [string]$Key,
    [string]$Value
  )

  [System.Reflection.Assembly]::LoadWithPartialName("System.Data.SQLite")
  $connString = "Data Source=$DB" 

  $conn = New-Object System.Data.SQLite.SQLiteConnection -ArgumentList $connString
  $conn.Open()
  $command = $conn.CreateCommand()
  $command.CommandText = "INSERT INTO $Table ($($Key)) VALUES (@Value1)"
  $command.Parameters.AddWithValue("@Value1", $Value)
  $command.ExecuteNonQuery()
  $conn.Close()
}
