# TrAIL
Trail Analysis and Integrity Logic - Tools for testing various sources of trail data.

## cotrex_url_test
Tests the URLs in the COTREX data to ensure that they work and lead to meaningful pages.  Redirects (301s, 302, <META http-equiv="refresh") are followed.  Final status codes other than 200 are recorded as an error.  Final results that contain the text "not found", "invalid url", or "something went wrong" are also flagged.  If multiple trails share the same URL, only the first is tested. The output is a CSV file that lists the COTREX id of the trail having an URL error, its name, its manager, and its URL.
																													  
>usage: cotrex_url_test [-h] [--limit LIMIT] COTREX_file output_file
>
>Tests whether the URLs in the COTREX data work
>
>positional arguments:
>  COTREX_file    File containing the COTREX data
>  output_file    File to which the errors should be written
>
>options:
>  -h, --help     show this help message and exit
>  --limit LIMIT  Limit number of records tested (for testing purposes)
