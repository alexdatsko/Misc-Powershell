#################################
# ChatGPT Chat shell
# Alex Datsko  1-6-23

# Set the API endpoint
$endpoint = "https://api.openai.com/v1/text-davinci/completions"
# Set the API key

$api_key = "sk-"   # Enter your API key here

$s = ""
while ($s.ToUpper() -ne "EXIT") {
  $s = Read-Host "What would you like to ask ChatGPT? (""exit""=quit) "
  # Set the request payload
  $payload = @{
    "prompt" = $s  # "What is the capital of France?"
    "max_tokens" = 10
  }
  # Set the headers
  $headers = @{
    "Authorization" = "Bearer $api_key"
  }
  # Send the POST request
  $response = Invoke-WebRequest -Uri $endpoint -Method POST -Body $payload -Headers $headers
  # Print the response
  $response.Content | ConvertFrom-Json
  
}
Write-Output "[.] Exiting!"