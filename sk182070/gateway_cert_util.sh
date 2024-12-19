#!/bin/bash

ECHO=/bin/echo
GREP=/bin/grep
CUT=/bin/cut
FOLD=/bin/fold
TAC=/bin/tac
TR=/bin/tr
XXD=/bin/xxd
DATE=/bin/date
PRINTF=/bin/printf
SORT=/bin/sort
AWK=/bin/awk
CAT=/bin/cat
SED=/bin/sed
REV=/bin/rev
DBGET=/usr/bin/dbget
WHICH=/bin/which
RM=/bin/rm

COMMANDS_FILE=/var/tmp/commands.txt
ONE_HUNDRED_YEARS=$((100*365))
ONE_YEAR_SECONDS=$((365*24*60*60))
MGMT_CLI_QUERY_LIMIT=500
USERNAME=""
PASSWORD=""
CREDENTIALS_SET=0
MDS_FORMAT="%-20s %-40s %-30s %-25s %-25s %-8s %-10s"
MGMT_FORMAT="%-20s %-40s %-25s %-25s %-8s %-10s"
GW_NAME_MAX_LEN=30
CMA_NAME_MAX_LEN=20

function update_pathnames()
{
	MGMT_CLI=$CPDIR/bin/mgmt_cli
	CPOPENSSL=$CPDIR/bin/cpopenssl
	CPCA_CLIENT=$FWDIR/bin/cpca_client
	FWM_CMD_CLIENT=$FWDIR/bin/fwm_cmd_client
	OBFUSCATE_PASSW=$FWDIR/bin/obfuscate_passw
}

function warning_message()
{
	$ECHO ""
	$ECHO "--------------------"
	$ECHO "$0: Warning: $1"
	$ECHO "--------------------"
	$ECHO ""
}

function error_message()
{
	$ECHO ""
	$ECHO "--------------------"
	$ECHO "$0: Error: $1"
	$ECHO "--------------------"
	$ECHO ""
}

function heavy_op_message()
{
	$ECHO ""
	$ECHO "--------------------"
	$ECHO "Viewing and renewing certificates is a resource-intensive operation."
	$ECHO "It can take up to 10 seconds per certificate."
	$ECHO "You must let the script run until completion."
	$ECHO "--------------------"
	$ECHO ""
}

function read_credentials()
{
	$ECHO ""
	$ECHO "Enter the credentials for the Management Server administrator:"
	read -p 'Username: ' USERNAME
	read -sp 'Password: ' PASSWORD
	$ECHO ""
}

function initialize()
{
	update_pathnames

	IS_MGMT=`cpprod_util FwIsFirewallMgmt`
	if [ "$IS_MGMT" -eq 0 ]; then
		error_message "This utility supports only Management Servers"
		exit 1
	fi

	parse_cli_arguments "$@"

	IS_MDS=0
	if [ ! -z $MDSDIR ]; then
		IS_MDS=1
	fi
}

function warning_handling_discard()
{
	MGMT_CLI_EXIT_CODE=$1
	MESSAGE=$2
	if [ $MGMT_CLI_EXIT_CODE -ne 0 ]; then
		warning_message "$MESSAGE"
		$MGMT_CLI discard --session-id $MGMT_API_SESSION >/dev/null 2>&1
	fi
}

function error_handling_discard()
{
	MGMT_CLI_EXIT_CODE=$1
	MESSAGE=$2
	if [ $MGMT_CLI_EXIT_CODE -ne 0 ]; then
		error_message "$MESSAGE"
		$MGMT_CLI discard --session-id $MGMT_API_SESSION >/dev/null 2>&1
	fi
}

function error_handling_logout()
{
	MGMT_CLI_EXIT_CODE=$1
	MESSAGE=$2
	error_handling_discard $MGMT_CLI_EXIT_CODE "$MESSAGE"
	$MGMT_CLI logout --session-id $MGMT_API_SESSION >/dev/null 2>&1
}

function truncate_string()
{
	local STR=$1
	local LEN=$2

	if (( ${#STR} > LEN )); then
		STR="${STR:0:LEN-3}..."
	fi

	$ECHO "$STR"
}

function usage_and_exit()
{
	$ECHO "------------"
	$ECHO "Usage:"
	$ECHO "------------"
	$ECHO "To show certificates:"
	$ECHO "   gateway_cert_util.sh -show {all | <max_days_until_expiration>} -type {vpn | broker | all} [-user <username> -pass <password>] [-format {json | csv}]"
	$ECHO ""
	$ECHO "To renew certificates:"
	$ECHO "   gateway_cert_util.sh -renew {all | <max_days_until_expiration>} -type {vpn | broker | all} [-user <username> -pass <password>] [-file <file_with_gateway_names>]"
	$ECHO ""
	$ECHO "Where '<max_days_until_expiration>' is counted from today (and up to 100 years)."
	$ECHO ""
	$ECHO "------------"
	$ECHO "Examples:"
	$ECHO "------------"
	$ECHO 'Show certificates of all types (VPN and Identity Broker), specify credentials in the command:'
	$ECHO '   $FWDIR/scripts/gateway_cert_util.sh -show all -type all -user admin -pass P@s$w@rd'
	$ECHO ""
	$ECHO 'Show certificates of type VPN that expire in 180 days (from today), and save the output in a JSON file:'
	$ECHO '   $FWDIR/scripts/gateway_cert_util.sh -show 180 -type vpn -format json'
	$ECHO ""
	$ECHO 'Show certificates of type Identity Broker that expire in 90 days (from today), and save the output in a CSV file:'
	$ECHO '   $FWDIR/scripts/gateway_cert_util.sh -show 90 -type broker -format csv'
	$ECHO ""
	$ECHO 'Renew certificates of all types (VPN and Identity Broker), specify credentials in the command:'
	$ECHO '   $FWDIR/scripts/gateway_cert_util.sh -renew all -type all -user admin -pass P@s$w@rd'
	$ECHO ""
	$ECHO 'Renew certificates of type VPN that expire in 90 days (from today):'
	$ECHO '   $FWDIR/scripts/gateway_cert_util.sh -renew 90 -type vpn'
	$ECHO ""
	$ECHO 'Renew certificates of type Identity Broker that expire in 180 days (from today):'
	$ECHO '   $FWDIR/scripts/gateway_cert_util.sh -renew 180 -type broker'
	$ECHO ""
	$ECHO 'Renew certificates of type Identity Broker for the specified Security Gateways:'
	$ECHO '   $FWDIR/scripts/gateway_cert_util.sh -renew all -type broker -file /home/admin/list_of_objects.txt'
	$ECHO ""
	$ECHO 'Renew certificates of all types that expire in 180 days (from today) for the specified Security Gateways:'
	$ECHO '   $FWDIR/scripts/gateway_cert_util.sh -renew 180 -type all -file /var/tmp/list_of_objects.txt'
	$ECHO ""

	exit 1
}

function parse_cli_arguments()
{
	if ([ "$#" -lt 2 ] || [ "$#" -gt 10 ]) || [ $(("$#" % 2)) -ne 0 ]; then
		error_message "Invalid number of arguments"
		usage_and_exit
	fi

	case "$1" in
		"-show")
			handle_days_argument "-show" "$2"
			shift 2
			handle_show_arguments "$@"
			;;
		"-renew")
			handle_days_argument "-renew" "$2"
			shift 2
			handle_renew_arguments "$@"
			;;
		*)
			error_message "The first argument must be '-show' or '-renew'"
			usage_and_exit
			;;
	esac

	if [ -z "$CERTIFICATE_TYPE" ]; then
		error_message "The argument '-type' is mandatory"
		usage_and_exit
	fi

	if [ ! -z "$USERNAME" ] || [ ! -z "$PASSWORD" ]; then
		handle_credential_arguments "$USERNAME" "$PASSWORD"
	fi
}

function handle_days_argument()
{
	CMD_ARG=$1 #'-show' or '-renew'
	DAYS_ARG=$2 #'all' or number of days

	if [ "$2" = "all" ]; then
		DAYS_UNTIL_EXPIRATION="$ONE_HUNDRED_YEARS"
	elif [ "$2" -ge 0 ] && [ "$2" -le "$ONE_HUNDRED_YEARS" ]; then
		# If a user enters some letters, then Bash will show "integer expression expected"
		DAYS_UNTIL_EXPIRATION="$2"
	else
		error_message "Invalid value for the argument \"$CMD_ARG\""
		usage_and_exit
	fi
}

function handle_show_arguments()
{
	while [[ $# -gt 0 ]]; do
		case "$1" in
			"-type")
				handle_cert_type_argument "$2"
				shift 2
				;;
			"-user")
				USERNAME="$2"
				shift 2
				;;
			"-pass")
				PASSWORD="$2"
				shift 2
				;;
			"-format")
				handle_format_argument "$2"
				shift 2
				;;
			*)
				error_message "Invalid argument: $1"
				usage_and_exit
				;;
		esac
	done
}

function handle_renew_arguments()
{
	RENEW_CERTIFICATES=1

	while [[ $# -gt 0 ]]; do
		case "$1" in
			"-type")
				handle_cert_type_argument "$2"
				shift 2
				;;
			"-user")
				USERNAME="$2"
				shift 2
				;;
			"-pass")
				PASSWORD="$2"
				shift 2
				;;
			"-file")
				RENEW_WITH_FILE=1
				GWS_FILE="$2"
				shift 2
				;;
			*)
				error_message "Invalid argument: $1"
				usage_and_exit
				;;
		esac
	done
}

function handle_cert_type_argument()
{
	if [ "$1" = "vpn" ] || [ "$1" = "broker" ] || [ "$1" = "all" ]; then
		CERTIFICATE_TYPE="$1"
	else
		error_message "Invalid value for the argument '-type'"
		usage_and_exit
	fi
}

function handle_credential_arguments()
{
	if [ -z "$USERNAME" ]; then
		error_message "The argument '-pass' requires the argument '-user'"
		usage_and_exit
	fi
	if [ -z "$PASSWORD" ]; then
		error_message "The argument '-user' requires the argument '-pass'"
		usage_and_exit
	fi
	CREDENTIALS_SET=1
}

function handle_format_argument() {
	FORMAT_ARG="$1"
	if [ "$FORMAT_ARG" = "json" ] || [ "$FORMAT_ARG" = "csv" ]; then
		OUTPUT_FORMAT="$FORMAT_ARG"
		OUTPUT_FILE="/var/tmp/certificates_${CERTIFICATE_TYPE}_$(date +%d-%b-%Y_%Hh-%Mm-%Ss).${OUTPUT_FORMAT}"
	else
		error_message "Invalid value for the argument '-format'"
		usage_and_exit
	fi
}

function handle_query_batch_results()
{
	MGMT_CLI_CMD=$1
	MGMT_CLI_ARGS=$2

	BATCH_OBJECTS=$($MGMT_CLI $MGMT_CLI_CMD limit $MGMT_CLI_QUERY_LIMIT details-level full $MGMT_CLI_ARGS)
	if [ $? -ne 0 ]; then
		error_message "This command failed: mgmt_cli $MGMT_CLI_CMD"
		BATCH_OBJECTS=""
		return
	fi

	TOTAL_OBJECTS=$(jq -r '.total' <<< "$BATCH_OBJECTS")
	# All results were returned in one batch
	if [ $TOTAL_OBJECTS -lt $MGMT_CLI_QUERY_LIMIT ]; then
		return
	fi

	OFFSET=$MGMT_CLI_QUERY_LIMIT

	# Some mgmt_cli commands return the actual total number of objects in the total field, while others return the limit value
	# We must handle both cases
	while [ $TOTAL_OBJECTS -ge $MGMT_CLI_QUERY_LIMIT ]
	do
		OBJECTS_IN_LOOP=$($MGMT_CLI $MGMT_CLI_CMD offset $OFFSET limit $MGMT_CLI_QUERY_LIMIT details-level full $MGMT_CLI_ARGS)
		TOTAL_OBJECTS=$(jq -r '.total' <<< "$OBJECTS_IN_LOOP")
		# Break the loop if there are no more objects
		if [ $TOTAL_OBJECTS -eq 0 ]; then
			break
		fi

		BATCH_OBJECTS=$(jq -s add <(jq .objects <<< "$BATCH_OBJECTS") <(jq .objects <<< "$OBJECTS_IN_LOOP") | jq -c '{objects: .}')
		OFFSET=$((OFFSET+MGMT_CLI_QUERY_LIMIT))
	done
}

function handle_all_cmas()
{
	CMA_LIST=`$MDSVERUTIL AllCMAs`
	CMAS_AND_DOMAINS_TUPLES=$(jq -r '.objects[] | select(.type == "checkpoint-host") | "\(.name),\(.domain.name)"' <<< "$GWS_AND_SERVERS_OUTPUT" \
		| sed 's/^"\(.*\)"$/\1/')
	for CMA_AND_DOMAIN in $CMAS_AND_DOMAINS_TUPLES; do
		CMA_NAME=$($ECHO "$CMA_AND_DOMAIN" | cut -d',' -f1)
		DOMAIN_NAME=$($ECHO "$CMA_AND_DOMAIN" | cut -d',' -f2)
		if [[ $CMA_LIST =~ (^|[[:space:]])$CMA_NAME($|[[:space:]]) ]]; then
			mdsenv "$CMA_NAME"
			update_pathnames
			handle_single_cma "$CMA_NAME" "$DOMAIN_NAME"
		fi
		# else - CMA_NAME is not part of the CMA List. For example, might be a Log Server. Skipping...
	done
}

function handle_cma_by_name()
{
	CMA_NAME=$1
	DOMAIN_NAME=$(jq -r '.objects[] | select(.type == "checkpoint-host") | select(.name == "'$CMA_NAME'").domain.name' <<< "$GWS_AND_SERVERS_OUTPUT")

	if [ -z "$DOMAIN_NAME" ]; then
		error_handling_logout 1 "Failed to get the Domain name for: $CMA_NAME"
		$ECHO "You must run the script from the MDS context (run the 'mdsenv' command)."
		$ECHO ""
		exit 1
	fi

	mdsenv "$CMA_NAME"
	update_pathnames
	handle_single_cma "$CMA_NAME" "$DOMAIN_NAME"
}

search_current_ica()
{
	local SUBJECT=$1
	local SERIAL=$2
	local CPCA_CLIENT_ARGS=$3

	CERTIFICATE_STATUS=$($CPCA_CLIENT lscert -dn "$SUBJECT" -ser "$SERIAL" | eval $CPCA_CLIENT_ARGS)
	ICA_CN=$($CPOPENSSL pkcs12 -in $FWDIR/conf/InternalCA.p12 -nokeys -nomacver -passin pass: 2>/dev/null \
		| $CPOPENSSL x509 -noout -issuer | $GREP -oP 'issuer=\K(.*)')
}

function search_all_cmas_ica()
{
	local SUBJECT=$1
	local SERIAL=$2
	local CPCA_CLIENT_ARGS=$3

	if [ $IS_MDS -ne 1 ]; then
		return
	fi

	if [ -z "$CMA_LIST" ]; then
		CMA_LIST=`$MDSVERUTIL AllCMAs`
		CMAS_AND_DOMAINS_TUPLES=$(jq -r '.objects[] | select(.type == "checkpoint-host") | "\(.name),\(.domain.name)"' <<< "$GWS_AND_SERVERS_OUTPUT" \
		| sed 's/^"\(.*\)"$/\1/')
	fi

	for CMA_AND_DOMAIN in $CMAS_AND_DOMAINS_TUPLES; do
		CMA=$($ECHO "$CMA_AND_DOMAIN" | cut -d',' -f1)
		DOMAIN=$($ECHO "$CMA_AND_DOMAIN" | cut -d',' -f2)
		if [[ $CMA_LIST =~ (^|[[:space:]])$CMA($|[[:space:]]) ]]; then
			if [ "$CMA" != "$CMA_NAME" ]; then
				mdsenv "$CMA"
				update_pathnames
				# Check if the ICA certificate is valid
				search_current_ica "$SUBJECT" "$SERIAL" "$CPCA_CLIENT_ARGS"
				if [ ! -z "$CERTIFICATE_STATUS" ]; then
					ICA_NAME="$CMA"
					OTHER_CMA_CERT=1
					break
				# Compare the ICA certificate subject to the Security Gateway's certificate issuer
				# to further validate if the certificate is from the ICA or not.
				# This is needed as an expired certificate will not be found in the ICA,
				# so we could end up renewing a certificate under the wrong Domain Management Server,
				# if the issuer is not validated to be the current Domain Management Server.
				elif [ ! -z "$ICA_CN" ] && [ "$ICA_CN" == "$CERTIFICATE_ISSUER" ]; then
					ICA_NAME="$CMA"
					OTHER_CMA_CERT=1
					break
				fi
			fi
		fi
		# else - CMA_NAME is not part of the CMA List. For example, might be a Log Server. Skipping...
	done

	# Check the MDS level if there was no match in the CMAs
	if [ "$OTHER_CMA_CERT" -ne 1 ]; then
		mdsenv
		update_pathnames
		search_current_ica "$SUBJECT" "$SERIAL" "$CPCA_CLIENT_ARGS"
		if [ ! -z "$CERTIFICATE_STATUS" ]; then
			ICA_NAME=""$HOSTNAME" - *MDS Level*"
			OTHER_CMA_CERT=1
		elif [ ! -z "$ICA_CN" ] && [ "$ICA_CN" == "$CERTIFICATE_ISSUER" ]; then
			ICA_NAME=""$HOSTNAME" - *MDS Level*"
			OTHER_CMA_CERT=1
		fi
	fi

	mdsenv "$CMA_NAME"
	update_pathnames
}

function set_certificate_status_color()
{
	case "$1" in
		"Valid")
			COLORED_CERTIFICATE_STATUS="\033[32mValid\033[0m"
			;;
		"External")
			COLORED_CERTIFICATE_STATUS="\033[33mExternal\033[0m"
			;;
		"Pending")
			COLORED_CERTIFICATE_STATUS="\033[33mPending\033[0m"
			;;
		"Expired")
			COLORED_CERTIFICATE_STATUS="\033[31mExpired\033[0m"
			;;
		"Revoked")
			COLORED_CERTIFICATE_STATUS="\033[31mRevoked\033[0m"
			;;
		"Error - Needs renewal")
			COLORED_CERTIFICATE_STATUS="\033[31mError - Needs renewal\033[0m"
			;;
		*)
			COLORED_CERTIFICATE_STATUS="\033[31mUnknown\033[0m"
			;;
	esac
}

function parse_certificate_bytes()
{
	CERTIFICATE_REVERSED=$1
	# DER or PEM
	CERTIFICATE_FORMAT=$2

	if [ -z "$CERTIFICATE_REVERSED" ]; then
		PARSE_ERR_MSG="Certificate byte buffer is empty."
		PARSE_SUCCESS=0
		return
	elif [ -z "$CERTIFICATE_FORMAT" ]; then
		PARSE_ERR_MSG="Certificate format is empty."
		PARSE_SUCCESS=0
		return
	fi

	# ICA uses a series of digits as the serial number (default is 5 and max is 10)
	ICA_SERIAL_REGEX="Serial Number:\s*\K\d+(?=\s+\()"
	OTHER_CMA_CERT=0
	# External CAs typically use a colon-separated hex string as the serial number
	EXTERNAL_CA_SERIAL_REGEX="Serial Number:\s+\K(?i)([0-9A-F]{2}:)*[0-9A-F]{2}"
	EXTERNAL_CA_CERT=0

	# The MGMT DB stores the certificate byte buffer in big-endian format. We need to convert it to little-endian.
	CERTIFICATE=`$ECHO $CERTIFICATE_REVERSED | $FOLD -w2 | $TAC | $TR -d "\n"`
	CERTIFICATE_INFO=$($ECHO "$CERTIFICATE" | $XXD -r -p | $CPOPENSSL x509 -inform "$CERTIFICATE_FORMAT" -noout -text \
		| awk '/Subject Public Key Info:/ {exit}1')
	CERTIFICATE_ISSUER=$($ECHO "$CERTIFICATE_INFO" | grep -oP 'Issuer: \K(.*)')
	# First, check if the certificate serial number matches the ICA serial number pattern
	CERTIFICATE_SERIAL=$($ECHO "$CERTIFICATE_INFO" | grep -oP "$ICA_SERIAL_REGEX")
	# Check if the certificate serial number matches the External CA serial number pattern
	# if the ICA pattern did not match
	if [ -z "$CERTIFICATE_SERIAL" ]; then
		CERTIFICATE_SERIAL=$($ECHO "$CERTIFICATE_INFO" | grep -ozP "$EXTERNAL_CA_SERIAL_REGEX" | $TR -d '\0')
		if [ -z "$CERTIFICATE_SERIAL" ]; then
			PARSE_ERR_MSG="Failed to extract the certificate serial number."
			PARSE_SUCCESS=0
			return
		fi
		EXTERNAL_CA_CERT=1
	fi
	CERTIFICATE_SUBJECT=$($ECHO "$CERTIFICATE_INFO" | grep -oP 'Subject: \K(.*)')
	CERTIFICATE_CREATION_DATE=$($ECHO "$CERTIFICATE_INFO" | grep -oP 'Not Before:\s*\K(.*)')
	CERTIFICATE_EXPIRATION_DATE=$($ECHO "$CERTIFICATE_INFO" | grep -oP 'Not After : \K(.*)')
	CERTIFICATE_EXPIRATION_DATE_EPOCH=`$DATE --date="$CERTIFICATE_EXPIRATION_DATE" +"%s"`
	TIME_NOW_EPOCH=`$DATE +"%s"`
	EXPIRATION_TIME_EPOCH=$((DAYS_UNTIL_EXPIRATION*24*60*60))
	EXPIRATION_FROM_NOW_EPOCH=$((TIME_NOW_EPOCH+EXPIRATION_TIME_EPOCH))
	SECONDS_UNTIL_EXPIRATION=$((CERTIFICATE_EXPIRATION_DATE_EPOCH-TIME_NOW_EPOCH))

	if [ "$EXTERNAL_CA_CERT" -eq 1 ]; then
		# Use "External" as the status for External CA certificates as we can only verify their validity by
		# expiration date from the parsed info (i.e. the certificate could be revoked by the issuing CA)
		CERTIFICATE_STATUS="External"
		# Color 'External' in yellow.
		COLORED_CERTIFICATE_STATUS="\033[33mExternal\033[0m"
	else
		CERTIFICATE_CN=$($ECHO "$CERTIFICATE_SUBJECT" | $GREP -oP "CN\s*=\s*\K(.*)" | sed 's/,.*//g')
		search_current_ica "$CERTIFICATE_CN" "$CERTIFICATE_SERIAL" "$GREP Status | $CUT -d' ' -f3"
		if [ -z "$CERTIFICATE_STATUS" ] && [ "$CERTIFICATE_ISSUER" != "$ICA_CN" ]; then
			# Check other CMAs
			search_all_cmas_ica "$CERTIFICATE_CN" "$CERTIFICATE_SERIAL" "$GREP Status | $CUT -d' ' -f3"
			if [ "$OTHER_CMA_CERT" -ne 1 ] && [ "$SECONDS_UNTIL_EXPIRATION" -gt 0 ]; then
				# The certificate could be issued from a different management server
				# We will treat it as an External CA certificate
				EXTERNAL_CA_CERT=1
				CERTIFICATE_STATUS="External"
			fi
		fi
		# Check if SECONDS_UNTIL_EXPIRATION is equal to, or less than 0 and CERTIFICATE_STATUS is empty
		if [ "$SECONDS_UNTIL_EXPIRATION" -le 0 ] && [ -z "$CERTIFICATE_STATUS" ]; then
			CERTIFICATE_STATUS="Expired"
		fi
	fi
	# In Standby MGMT, the cpca_client does not work, so we can rely on the date only, and assume the cert is valid.
	if [ $IS_ACTIVE -eq 0 ]; then
		if [ "$SECONDS_UNTIL_EXPIRATION" -gt 0 ]; then
			CERTIFICATE_STATUS="Valid"
		fi
	fi

	# Set certificates in an error state to be displayed by the 'show' command and renewed by the 'renew' command
	# "Renewed" status typically occurs when a previous renewal did not complete successfully
	if [ "$CERTIFICATE_STATUS" = "Renewed" ] || [ "$CERTIFICATE_STATUS" = "Error" ]; then
		CERTIFICATE_STATUS="Error - Needs renewal"
		CERTIFICATE_EXPIRATION_DATE_EPOCH=$(($TIME_NOW_EPOCH-$ONE_YEAR_SECONDS))
	fi

	set_certificate_status_color "$CERTIFICATE_STATUS"
}

function create_output_file()
{
	GW_NAME_KEY="Gateway"
	CERT_SUBJECT_KEY="Subject"
	CERT_VAL_BEFORE_KEY="Not Valid Before"
	CERT_VAL_AFTER_KEY="Not Valid After"
	CERT_SERIAL_KEY="Serial No."
	CERT_STATUS_KEY="Status"
	CERT_TYPE_KEY="Type"

	if [ "$OUTPUT_FORMAT" = "json" ]; then
		NEW_OBJ=$(jq -n \
			--arg gw "$GW_NAME" \
			--arg subject "$CERTIFICATE_SUBJECT" \
			--arg val_before "$CERTIFICATE_CREATION_DATE" \
			--arg val_after "$CERTIFICATE_EXPIRATION_DATE" \
			--arg serial "$CERTIFICATE_SERIAL" \
			--arg status "$CERTIFICATE_STATUS" \
			--arg type "$TYPE_ARG" \
			'{
				gateway: $gw,
				subject: $subject,
				validityPeriod: {
					notValidBefore: $val_before,
					notValidAfter: $val_after
				},
				serialNumber: $serial,
				status: $status,
				type: $type
			}' \
		)

		if [ ! -e $OUTPUT_FILE ]; then
			OBJ_ARR=$(jq -n '{certificates: []}')
		else
			OBJ_ARR=$(<"$OUTPUT_FILE")
		fi

		MAIN_OBJ=$(jq '.certificates += ['"$NEW_OBJ"']' <<< "$OBJ_ARR")
		$ECHO "$MAIN_OBJ" > "$OUTPUT_FILE"
	elif [ "$OUTPUT_FORMAT" = "csv" ]; then
		if [ ! -e $OUTPUT_FILE ]; then
			$PRINTF "%s,%s,%s,%s,%s,%s,%s\n" \
				\""$GW_NAME_KEY"\" \
				\""$CERT_SUBJECT_KEY"\" \
				\""$CERT_VAL_BEFORE_KEY"\" \
				\""$CERT_VAL_AFTER_KEY"\" \
				\""$CERT_SERIAL_KEY"\" \
				\""$CERT_STATUS_KEY"\" \
				\""$CERT_TYPE_KEY"\" > "$OUTPUT_FILE"
		fi

		$PRINTF "%s,%s,%s,%s,%s,%s,%s\n" \
			\""$GW_NAME"\" \
			\""$CERTIFICATE_SUBJECT"\" \
			\""$CERTIFICATE_CREATION_DATE"\" \
			\""$CERTIFICATE_EXPIRATION_DATE"\" \
			\""$CERTIFICATE_SERIAL"\" \
			\""$CERTIFICATE_STATUS"\" \
			\""$TYPE_ARG"\" >> "$OUTPUT_FILE"
	fi
}

function create_pkcs12_file()
{
	TMP_PKCS12_FILE=/var/tmp/gw_broker.p12

	PASS=`$CPOPENSSL rand -hex 32`
	if [ $? -ne 0 ]; then
		error_message "Failed to generate random bytes"
		return
	fi

	PASS_OBS=`$OBFUSCATE_PASSW "$PASS"`
	EXIT_CODE=$?
	if [ "$EXIT_CODE" -ne 0 ]; then
		error_message "Failed to obfuscate the password. Exit code: $EXIT_CODE"
		return
	fi

	$CPCA_CLIENT create_cert -n "$SUBJECT" -f "$TMP_PKCS12_FILE" -k IKE -w "$PASS" >/dev/null 2>&1
}

function parse_pkcs12_buf()
{
	if [ -z "$PKCS12BUF" ]; then
		PARSE_ERR_MSG="PKCS12 buffer is empty."
		PARSE_SUCCESS=0
		return
	fi

	# Get the certificates from the PKCS12 buffer in PEM format
	$ECHO "(
		:pkcs12-pem-fetch (
			:command (convert-p12-to-pem)
			:set (
				:p12_buffer ($PKCS12BUF)
				:password ()
				:use_cp_password (true)
				:server_cert_first_in_pem (true)
				:password_is_encoded (false)
			)
		)
	)" > $COMMANDS_FILE

	$FWM_CMD_CLIENT $COMMANDS_FILE pkcs12-pem-fetch >> /dev/null 2>&1
	EXIT_CODE=$?
	if [ $EXIT_CODE -ne 0 ]; then
		PARSE_ERR_MSG="This command failed: fwm_cmd_client pkcs12-pem-fetch"
		PARSE_SUCCESS=0
		return
	fi

	# Extract the certificate chains from the last reply
	CERT_CHAINS=$($CAT last_reply.txt | $SED -n '/:cert_chains (/,/))/p')
	if [ -z "$CERT_CHAINS" ]; then
		PARSE_ERR_MSG="Failed to extract the certificate chains from the 'fwm_cmd_client' 'last_reply.txt'"
		PARSE_SUCCESS=0
		return
	fi

	# Read the certificates from the certificate chains into an array
	CERT_ARRAY=()
	while IFS= read -r line; do
		if [[ $line = *":0 ("* || $line = *":1 ("* ]]; then
			CERT=$($ECHO "$line" | sed 's/^[^:]*:[0-9] //' | tr -d '()')
			if [ ! -z "$CERT" ]; then
				CERT_ARRAY+=("$CERT")
			fi
		fi
	done <<< "$CERT_CHAINS"

	# Loop over the certificate array and find the certificate with the same subject as the current certificate we are handling
	CERT_MATCH=0
	for CERT in "${CERT_ARRAY[@]}"
	do
		parse_certificate_bytes "$CERT" "PEM"
		if [ $PARSE_SUCCESS -eq 0 ]; then
			break
		fi
		# THE CN from the GEN_OBJ
		OBJ_CN=$($ECHO "$SUBJECT" | $GREP -oP "CN\s*=\s*\K(.*)" | sed 's/,.*//g')
		# The CN from the PEM certificate
		PEM_CN=$($ECHO "$CERTIFICATE_SUBJECT" | $GREP -oP "CN\s*=\s*\K(.*)" | sed 's/,.*//g')
		if [ "$OBJ_CN" = "$PEM_CN" ]; then
			CERT_MATCH=1
			break
		fi
	done

	if [ $CERT_MATCH -eq 0 ]; then
		PARSE_ERR_MSG="Failed to find a matching certificate in the fetched certificate chains."
		PARSE_SUCCESS=0
		return
	fi
}

function parse_cert_obj()
{
	PARSE_SUCCESS=1

	if [ "$TYPE_ARG" = "vpn" ]; then
		CERT_OBJ_ID=$($ECHO "$GEN_OBJ_CERTS" | jq -r ".[$CERT_INDEX].objId")
		PKISIGNKEY=$($ECHO "$GEN_OBJ_CERTS" | jq -r ".[$CERT_INDEX].pkisignkey")
		STORED_AT=$($ECHO "$GEN_OBJ_CERTS" | jq -r ".[$CERT_INDEX].storedAt")
		SUBJECT=$($ECHO "$GEN_OBJ_CERTS" | jq -r ".[$CERT_INDEX].dn")
		OWNED_NAME=$($ECHO "$GEN_OBJ_CERTS" | jq -r ".[$CERT_INDEX].ownedName")
		HASHSTRING_QUERY=".objects[] | select (.hashString==\"$PKISIGNKEY\")"
		CERTIFICATE_REVERSED=$(jq -r "$HASHSTRING_QUERY" <<< "$BLOBAUTHKEY_OBJECTS" | $GREP -oP ":cert \(\K[^)]+")
		parse_certificate_bytes "$CERTIFICATE_REVERSED" "DER"
	elif [ "$TYPE_ARG" = "broker" ]; then
		CERT_OBJ_ID=$($ECHO "$GEN_OBJ_CERTS" | jq -r ".[$CERT_INDEX].objId")
		DNS_CERT_UID=$($ECHO $GEN_OBJ_CERTS | jq -r ".[$CERT_INDEX].sslCertificate")
		DNS_PATTERN_CERT=$($MGMT_CLI show generic-object uid "$DNS_CERT_UID" $DOMAIN_ARG --session-id $MGMT_API_SESSION \
			--port $PORT --format json)
		SUBJECT=$($ECHO $DNS_PATTERN_CERT | jq -r '.dn')
		PKCS12BUF=$($ECHO $DNS_PATTERN_CERT | jq -r '.pkcs12buf')
		parse_pkcs12_buf
	fi
}

function create_blob_auth_key_obj()
{
	KEY=`$SED -n '/:key (/,/:reason (/p' last_reply.txt | head -n -1`
	PKISIGNKEY_NEW=`$CAT last_reply.txt | $GREP key-id | $CUT -d "(" -f2 | $CUT -d ")" -f1`
	if [ -z "$KEY" ] || [ -z "$PKISIGNKEY_NEW" ]; then
		error_message "The 'fwm_cmd_client' 'last_reply.txt' does not contain the expected key information"
		CREATE_OBJ_SUCCESS=0
		return
	fi

	BLOBSET=`$ECHO "($PKISIGNKEY_NEW
		:type (keyh)
		: (
			:obj (
				:type (refobj)
				:refname (\"#_$GW_NAME\")
			)
			:type (rsapkikey)
			$KEY
		)
	)"`

	$MGMT_CLI add-generic-object blobSet "$BLOBSET" hashString "$PKISIGNKEY_NEW" create "com.checkpoint.management.ngm_auth_keys.objects.BlobAuthKey" \
		$DOMAIN_ARG --session-id $MGMT_API_SESSION --port $PORT >/dev/null 2>&1
	EXIT_CODE=$?
	if [ $EXIT_CODE -ne 0 ]; then
		error_message "This command failed: mgmt_cli add-generic-object"
		CREATE_OBJ_SUCCESS=0
		return
	fi

	GEN_OBJ_ATTR="pkisignkey"
	GEN_OBJ_VAL="$PKISIGNKEY_NEW"
}

function create_pkcs12_cert_obj()
{
	PKCS12BUF=`$CAT last_reply.txt | $GREP ":pkcs12buf (" | $CUT -d "(" -f2 | $CUT -d ")" -f1`
	PKISIGNKEY=`$CAT last_reply.txt | $GREP ":pkisignkey (" | $CUT -d "(" -f2 | $CUT -d ")" -f1`
	VALID_TO=`$CAT last_reply.txt | $GREP ":valid_to (" | $CUT -d "(" -f2 | $CUT -d ")" -f1`
	DN=`$CAT last_reply.txt | $GREP ":dn (" | $CUT -d "(" -f2 | $CUT -d ")" -f1`
	VALID_FROM=`$CAT last_reply.txt | $GREP ":valid_from (" | $CUT -d "(" -f2 | $CUT -d ")" -f1`
	CERTIFICATE_NAME=`$CAT last_reply.txt | $GREP ":certificate_name (" | $CUT -d "(" -f2 | $CUT -d ")" -f1`
	DOUBLE_SIGN_CERT=`$CAT last_reply.txt | $GREP ":doubleSignCert (" | $CUT -d "(" -f2 | $CUT -d ")" -f1`
	ISSUER=`$CAT last_reply.txt | $GREP ":issuer (" | $CUT -d "(" -f2 | $CUT -d ")" -f1`

	# Generate a random suffix for the new certificate object
	GENERIC_OBJ_NAME_RAND_ENDING=`$CPOPENSSL rand -hex 10`
	EXIT_CODE=$?
	if [ "$EXIT_CODE" -ne 0 ]; then
		error_message "Failed to generate random bytes"
		CREATE_OBJ_SUCCESS=0
		return
	fi

	GENERIC_OBJ_NAME=cert_"$GENERIC_OBJ_NAME_RAND_ENDING"

	$MGMT_CLI add-generic-object create "com.checkpoint.objects.ssl_classes.dummy.CpmiPkcs12cert" name "$GENERIC_OBJ_NAME" \
		$DOMAIN_ARG --session-id $MGMT_API_SESSION --port $PORT >/dev/null 2>&1
	EXIT_CODE=$?
	if [ $EXIT_CODE -ne 0 ]; then
		error_message "This command failed: mgmt_cli add-generic-object"
		CREATE_OBJ_SUCCESS=0
		return
	fi

	GENERIC_OBJ_UID=`$MGMT_CLI show-generic-objects name "$GENERIC_OBJ_NAME" $DOMAIN_ARG --session-id $MGMT_API_SESSION \
		--port $PORT | $GREP "\- uid:" | $CUT -d "\"" -f2`

	$MGMT_CLI set-generic-object uid "$GENERIC_OBJ_UID" pkcs12buf "$PKCS12BUF" pkisignkey "$PKISIGNKEY" validTo "$VALID_TO" \
		dn "$DN" validFrom "$VALID_FROM" certificateName "$CERTIFICATE_NAME" doubleSignCert "$DOUBLE_SIGN_CERT" issuer \
		"$ISSUER" $DOMAIN_ARG --session-id $MGMT_API_SESSION --port $PORT

	EXIT_CODE=$?
	if [ $EXIT_CODE -ne 0 ]; then
		error_message "This command failed: mgmt_cli set-generic-object"
		CREATE_OBJ_SUCCESS=0
		return
	fi

	GEN_OBJ_ATTR="sslCertificate"
	GEN_OBJ_VAL="$GENERIC_OBJ_UID"
}

function gen_fwm_renew_command()
{
	if [ "$TYPE_ARG" = "vpn" ]; then
		RENEW_CMD="vpn-cert-renew"
		$ECHO "(
			:"$RENEW_CMD" (
				:command (gen-pki-cert-req)
				:set (
					:object (
						:is_owned (false)
						:status (signed)
						:dn (\"$SUBJECT\")
						:generated_by_auto_enrollment (true)
						:stored.at ($STORED_AT)
						:pkisignkey ($PKISIGNKEY)
						:\"#name\" (ReferenceObject
							:Name ($GW_NAME)
						)
						:certname ($OWNED_NAME)
					)
					:automatic (1)
					:internal (1)
					:renew (1)
					:alt_names (
						: (
							: (\"IP Address\")
							: ($CERTIFICATE_SAN)
						)
					)
					:database ()
				)
			)
		)" > $COMMANDS_FILE
	elif [ "$TYPE_ARG" = "broker" ]; then
		RENEW_CMD="import-ida-cert"
		$ECHO "(
			:"$RENEW_CMD" (
				:command (import-pkcs-12-cert)
				:set (
					:buffer ($PKCS12BUF)
					:password ($PASS_OBS)
					:database ()
				)
			)
		)" > $COMMANDS_FILE
	fi
}

function renew_single_cert()
{
	$ECHO "Renewing the certificate of type \"$TYPE_ARG\" for the Security Gateway: $GW_NAME"

	if [ "$EXTERNAL_CA_CERT" -eq 1 ] || [ "$OTHER_CMA_CERT" -eq 1 ]; then
		local WARNING
		if [ "$EXTERNAL_CA_CERT" -eq 1 ]; then
			read -r -d "" WARNING <<-EOM
				\nThe $TYPE_ARG certificate for the Security Gateway $GW_NAME is issued from an External CA.
				Renew the certificate on the issuing CA and then import the new certificate.
			EOM
			FAILED_TO_RENEW_EXTERNAL_CERT=$((FAILED_TO_RENEW_EXTERNAL_CERT+1))
		elif [ "$OTHER_CMA_CERT" -eq 1 ]; then
			read -r -d "" WARNING <<-EOM
				\nThe $TYPE_ARG certificate for the Security Gateway $GW_NAME is issued from a different Domain Management Server ($ICA_NAME) than the current Domain Management Server ($CMA_NAME).
				Renew the certificate manually on the Domain Management Server that issued this certificate.
			EOM
			FAILED_TO_RENEW_OTHER_CMA_CERT=$((FAILED_TO_RENEW_OTHER_CMA_CERT+1))
		fi

		warning_handling_discard 1 "$WARNING"
		return;
	fi

	if [ "$TYPE_ARG" = "vpn" ]; then
		if [ -z "$CERTIFICATE_SAN" ]; then
			error_handling_discard 1 "Failed to renew a certificate. The object $GW_NAME does not have an IP address."
			FAILED_TO_RENEW=$((FAILED_TO_RENEW+1))
			return
		fi
		SET_OBJ_PREFIX=".certificates.set.$CERT_INDEX"
		CREATE_OBJ_CMD="create_blob_auth_key_obj"
	elif [ "$TYPE_ARG" = "broker" ]; then
		create_pkcs12_file
		PKCS12BUF=`$CAT $TMP_PKCS12_FILE | $XXD -p | $TR -d "\n" | $FOLD -w2 | $TAC | $TR -d "\n"`
		# Clean up the temporary PKCS12 file
		$RM -f $TMP_PKCS12_FILE >/dev/null 2>&1
		if [ -z "$PKCS12BUF" ]; then
			error_handling_discard 1 "Failed to renew a certificate. The certificate of the object $GW_NAME does not have a PKCS12 buffer."
			FAILED_TO_RENEW=$((FAILED_TO_RENEW+1))
			return
		fi
		SET_OBJ_PREFIX="dnsPatternCertificates.set.$CERT_INDEX"
		CREATE_OBJ_CMD="create_pkcs12_cert_obj"
	fi

	# Generate the 'fwm_cmd_client' command for renewing the current certificate type
	gen_fwm_renew_command

	$FWM_CMD_CLIENT $COMMANDS_FILE "$RENEW_CMD" >> /dev/null 2>&1
	EXIT_CODE=$?
	if [ $EXIT_CODE -ne 0 ]; then
		error_handling_discard $EXIT_CODE "This command failed: fwm_cmd_client $RENEW_CMD"
		FAILED_TO_RENEW=$((FAILED_TO_RENEW+1))
		return
	fi

	# Create the new certificate object
	CREATE_OBJ_SUCCESS=1
	eval "$CREATE_OBJ_CMD"
	if [ $CREATE_OBJ_SUCCESS -eq 0 ]; then
		error_handling_discard 1 "Failed to create the new certificate object"
		FAILED_TO_RENEW=$((FAILED_TO_RENEW+1))
		return
	fi

	# Update the GW object with new certificate object
	$MGMT_CLI set-generic-object uid "$GW_UID" "$SET_OBJ_PREFIX".uid "$CERT_OBJ_ID" "$SET_OBJ_PREFIX".owned-object."$GEN_OBJ_ATTR" \
		"$GEN_OBJ_VAL" $DOMAIN_ARG --session-id $MGMT_API_SESSION --port $PORT >/dev/null 2>&1
	EXIT_CODE=$?
	if [ $EXIT_CODE -ne 0 ]; then
		error_handling_discard $EXIT_CODE "This command failed: mgmt_cli set-generic-object"
		FAILED_TO_RENEW=$((FAILED_TO_RENEW+1))
		return
	fi

	SUCCESSFULLY_RENEWED=$((SUCCESSFULLY_RENEWED+1))
	#Publish changes after each successful renew
	$MGMT_CLI publish --session-id $MGMT_API_SESSION --port $PORT >/dev/null 2>&1
}

function handle_single_cert()
{
	GW_UID=$1
	GW_NAME=$2
	CMA_NAME=$3
	DOMAIN_ARG=$4
	RENEW_CERTIFICATES=$5
	DAYS_UNTIL_EXPIRATION=$6
	TYPE_ARG=$7

	GEN_OBJ_INFO=$($MGMT_CLI show generic-object uid "$GW_UID" $DOMAIN_ARG --session-id $MGMT_API_SESSION --port $PORT --format json)

	if [ "$TYPE_ARG" = "vpn" ]; then
		CERTIFICATE_SAN=$(jq '.ipaddr' <<< "$GEN_OBJ_INFO")
		GEN_OBJ_ATTR=".certificates"
		CERTIFICATE_QUERY_KEY=".generatedByAutoEnrollment"
		CERTIFICATE_QUERY_VAL="true"
	elif [ "$TYPE_ARG" = "broker" ]; then
		GEN_OBJ_ATTR=".dnsPatternCertificates"
		CERTIFICATE_QUERY_KEY=".dnsPattern"
		CERTIFICATE_QUERY_VAL="broker.portal"
	fi

	GEN_OBJ_CERTS=$(jq "$GEN_OBJ_ATTR" <<< "$GEN_OBJ_INFO")

	if [[ -z "$GEN_OBJ_CERTS" || "$GEN_OBJ_CERTS" = "[]" ]]; then
		error_handling_discard 0 "No certificates found, or received a null response."
		return
	fi

	CERT_INDEX=-1
	# Loop over the array to find the index of the certificate with for the current certificate type
	index=0
	while IFS= read -r certificate; do
		if [[ $($ECHO "$certificate" | jq -r "$CERTIFICATE_QUERY_KEY") = "$CERTIFICATE_QUERY_VAL" ]]; then
			CERT_INDEX=$index
			break
		fi
		index=$((index + 1))
	done < <($ECHO "$GEN_OBJ_CERTS" | jq -c '.[]?')

	if [ $CERT_INDEX -eq -1 ]; then
		error_handling_discard 0 "No certificates found for the current certificate type."
		return
	fi

	# Parse the certificate object
	parse_cert_obj
	if [ $PARSE_SUCCESS -eq 0 ]; then
		local ERROR
		read -r -d "" ERROR <<-EOM
			\nFailed to parse the certificate: $SUBJECT
			Error details: $PARSE_ERR_MSG
		EOM
		error_handling_discard 1 "$ERROR"
		return
	fi

	if [ $RENEW_CERTIFICATES -eq 0 ]; then # Show command implementation
		SECONDS_UNTIL_EXPIRATION=$((CERTIFICATE_EXPIRATION_DATE_EPOCH-TIME_NOW_EPOCH))
		DAYS_UNTIL_EXPIRATION_CUR=$($ECHO "scale=2; $SECONDS_UNTIL_EXPIRATION/(60*60*24)" | bc)
		# round the result
		DAYS_UNTIL_EXPIRATION_CUR=$($ECHO "($DAYS_UNTIL_EXPIRATION_CUR+0.5)/1" | bc)
		if (( DAYS_UNTIL_EXPIRATION_CUR <= DAYS_UNTIL_EXPIRATION )); then
			CERTIFICATE_COUNT=$((CERTIFICATE_COUNT+1))
			GW_NAME_TRUNC=$(truncate_string "$GW_NAME" "$GW_NAME_MAX_LEN")
			if [ $IS_MDS -eq 1 ]; then
				CMA_NAME_TRUNC=$(truncate_string "$CMA_NAME" "$CMA_NAME_MAX_LEN")
				CERTIFICATES_LIST="$CERTIFICATES_LIST"$($PRINTF "$MDS_FORMAT" \
					"$DAYS_UNTIL_EXPIRATION_CUR" "$GW_NAME_TRUNC" "$CMA_NAME_TRUNC" "$CERTIFICATE_CREATION_DATE" \
					"$CERTIFICATE_EXPIRATION_DATE" "$TYPE_ARG" "$COLORED_CERTIFICATE_STATUS")"\n"
			else
				CERTIFICATES_LIST="$CERTIFICATES_LIST"$($PRINTF "$MGMT_FORMAT" \
					"$DAYS_UNTIL_EXPIRATION_CUR" "$GW_NAME_TRUNC" "$CERTIFICATE_CREATION_DATE" \
					"$CERTIFICATE_EXPIRATION_DATE" "$TYPE_ARG" "$COLORED_CERTIFICATE_STATUS")"\n"
			fi

			# Create output file if requested
			if [ ! -z "$OUTPUT_FORMAT" ]; then
				create_output_file >/dev/null 2>&1
				EXIT_CODE=$?
				if [ $EXIT_CODE -ne 0 ]; then
					$OUTPUT_ERROR=1
				fi
			fi
		fi
	else # Renew command implementation
		if (( CERTIFICATE_EXPIRATION_DATE_EPOCH < EXPIRATION_FROM_NOW_EPOCH )); then
			CERTIFICATES_TO_RENEW=$((CERTIFICATES_TO_RENEW+1))
			# Renew the certificate
			renew_single_cert
		fi
	fi
}

function handle_single_cma()
{
	CMA_NAME=$1
	DOMAIN_NAME=$2

	if [ $IS_MDS -eq 1 ]; then
		DOMAIN_ARG="-d ""$DOMAIN_NAME"
	else
		DOMAIN_ARG=""
	fi

	READ_ONLY_MODE=0
	IS_ACTIVE=`cpprod_util CPPROD_GetValue "FW1" "ActiveManagement" 1`
	if [ $IS_ACTIVE -eq 0 ]; then
		if [ $RENEW_CERTIFICATES -eq 1 ];then
			if [ $IS_MDS -eq 1 ]; then
				$ECHO "The status of the Domain $DOMAIN_NAME is not Active. Skipping to the next Domain."
			else
				$ECHO "The status of the Management Server is not Active."
			fi
			$ECHO "Renewal of certificates is allowed only from Domains in the Active status."
			$ECHO ""
			return
		else
			# Inactive domain in show flow
			READ_ONLY_MODE=1
		fi
	fi
	if [ $READ_ONLY_MODE -eq 1 ]; then
		#session-name/session-comments/session-description are unexpected, when login is done in the readonly mode."
		#Login in read-only mode.
		MGMT_API_SESSION=`$MGMT_CLI $DOMAIN_ARG login user $USERNAME password $PASSWORD read-only true --format json --port $PORT` >/dev/null 2>&1
	else
		MGMT_API_SESSION=`$MGMT_CLI $DOMAIN_ARG login user $USERNAME password $PASSWORD session-name "VPN Renewal Script" session-description \
			"Operations to display or renew VPN certificates" --format json --port $PORT` >/dev/null 2>&1
	fi

	EXIT_CODE=$?
	if [ $EXIT_CODE -ne 0 ]; then
		message=$($ECHO "$MGMT_API_SESSION" | jq -r '.message')
		# Check if the message matches the desired string
		if [ "$message" = "Administrator account is locked." ]; then
			error_message "Administrator account is locked. Follow sk142373."
		else
			error_message "The command 'mgmt_cli login' failed for the Domain $DOMAIN_NAME with this message: $message"
		fi
		return
	fi
	MGMT_API_SESSION=$($ECHO "$MGMT_API_SESSION" | jq -r '.sid')
	if [ $IS_MDS -eq 1 ]; then
		handle_query_batch_results "show-gateways-and-servers" "$DOMAIN_ARG --session-id $MGMT_API_SESSION \
			--port $PORT --format json"
		if [ -z "$BATCH_OBJECTS" ]; then
			error_handling_logout 1 "There are no Security Gateways in the Domain $DOMAIN_NAME"
			return
		fi
		MGMT_OR_DOMAIN_OBJECTS="$BATCH_OBJECTS"
	else
		MGMT_OR_DOMAIN_OBJECTS="$GWS_AND_SERVERS_OUTPUT"
	fi

	GW_UIDS=($(jq -r '.objects[].uid' <<< "$MGMT_OR_DOMAIN_OBJECTS"))
	GW_NAMES=($(jq -r '.objects[].name' <<< "$MGMT_OR_DOMAIN_OBJECTS"))
	GW_TYPES=($(jq -r '.objects[].type' <<< "$MGMT_OR_DOMAIN_OBJECTS"))

	if [ "$CERTIFICATE_TYPE" = "all" ] || [ "$CERTIFICATE_TYPE" = "vpn" ]; then
		BLOBAUTHKEY_CLASS="\"com.checkpoint.management.ngm_auth_keys.objects.BlobAuthKey\""
		handle_query_batch_results "show-generic-objects" "class-name $BLOBAUTHKEY_CLASS $DOMAIN_ARG \
			--session-id $MGMT_API_SESSION --port $PORT --format json"
		if [ -z "$BATCH_OBJECTS" ] && [ "$CERTIFICATE_TYPE" = "vpn" ]; then
			error_handling_logout 1 "There are no VPN certificates in the Domain $DOMAIN_NAME"
			return
		fi
		BLOBAUTHKEY_OBJECTS="$BATCH_OBJECTS"
	fi

	for ((i=0; i<${#GW_UIDS[@]}; i++)); do
		GW_SEARCH_RES=0
		if [ "$RENEW_CERTIFICATES" -eq 1 ] && [ "$RENEW_WITH_FILE" -eq 1 ]; then
			$GREP -q "^"${GW_NAMES[i]}"$" "$GWS_FILE"
			GW_SEARCH_RES=$?
		fi
		if [ "${GW_TYPES[i]}" = "simple-gateway" ] || [ "${GW_TYPES[i]}" = "cluster-member" ] || [ "${GW_TYPES[i]}" = "CpmiGatewayCluster" ] \
			|| [ "${GW_TYPES[i]}" = "CpmiVsxNetobj" ] || [ "${GW_TYPES[i]}" = "CpmiVsNetobj" ] || [ "${GW_TYPES[i]}" = "CpmiVsxClusterNetobj" ] \
			|| [ "${GW_TYPES[i]}" = "CpmiVsClusterNetobj" ]; then
			if [ "$RENEW_CERTIFICATES" -eq 0 ] || ([ "$RENEW_CERTIFICATES" -eq 1 ] && [ $GW_SEARCH_RES -eq 0 ]); then
				if [ "$CERTIFICATE_TYPE" = "all" ]; then
					# Execute 'handle_single_cert' twice for each Security Gateway - once for VPN and once for Identity Broker
					if [ ! -z "$BLOBAUTHKEY_OBJECTS" ]; then
						handle_single_cert "${GW_UIDS[i]}" "${GW_NAMES[i]}" "$CMA_NAME" "$DOMAIN_ARG" "$RENEW_CERTIFICATES" "$DAYS_UNTIL_EXPIRATION" "vpn"
					fi
					handle_single_cert "${GW_UIDS[i]}" "${GW_NAMES[i]}" "$CMA_NAME" "$DOMAIN_ARG" "$RENEW_CERTIFICATES" "$DAYS_UNTIL_EXPIRATION" "broker"
				else
					handle_single_cert "${GW_UIDS[i]}" "${GW_NAMES[i]}" "$CMA_NAME" "$DOMAIN_ARG" "$RENEW_CERTIFICATES" "$DAYS_UNTIL_EXPIRATION" "$CERTIFICATE_TYPE"
				fi
			fi
		fi
	done
	$MGMT_CLI publish --session-id $MGMT_API_SESSION --port $PORT >/dev/null 2>&1
	$MGMT_CLI logout --session-id $MGMT_API_SESSION --port $PORT >/dev/null 2>&1
}

READ_ONLY_MODE=0
IS_ACTIVE=`cpprod_util CPPROD_GetValue "FW1" "ActiveManagement" 1`
if [ $IS_ACTIVE -eq 0 ]; then
	READ_ONLY_MODE=1
fi

$WHICH fwm_cmd_client >/dev/null 2>&1
EXIT_CODE=$?
if [ "$EXIT_CODE" -ne 0 ]; then
	error_message "This Management Server does not meet the requirements. See sk182070."
	exit 1
fi

RENEW_CERTIFICATES=0
RENEW_WITH_FILE=0

initialize "$@"

# Renew with file_with_gateway_names
if [ "$RENEW_WITH_FILE" -eq 1 ]; then
	if [ -f "$GWS_FILE" ]; then
		dos2unix $GWS_FILE >/dev/null 2>&1
	else
		error_message "The provided file with Security Gateway object names does not exist"
		exit 1
	fi
fi

# Get user and password for 'mgmt_cli' commands.
PORT=`$DBGET httpd:ssl_port`
READ_ATTEMPTS=0
EXIT_CODE=1
while [ $EXIT_CODE -ne 0 ]; do
	if [ $CREDENTIALS_SET -eq 0 ]; then
		read_credentials
	fi

	READ_ATTEMPTS=$((READ_ATTEMPTS+1))

	if [ $READ_ONLY_MODE -eq 1 ]; then
		#session-name/session-comments/session-description are unexpected, when login is done in the readonly mode."
		#Login in read-only mode.
		TEST_SESSION=`$MGMT_CLI login user $USERNAME password $PASSWORD read-only true --format json --port $PORT` >/dev/null 2>&1
	else
		TEST_SESSION=`$MGMT_CLI login user $USERNAME password $PASSWORD session-name "VPN Script Credentials Test" session-description \
			"Login to test credentials correctness" --port $PORT --format json` >/dev/null 2>&1
	fi
	EXIT_CODE=$?

	if [ $EXIT_CODE -ne 0 ]; then
		message=$($ECHO "$TEST_SESSION" | jq -r '.message')
		# Check if the message matches the desired string
		if [ "$message" = "Administrator account is locked." ]; then
			error_message "Administrator account is locked. Follow sk142373."
			exit 1
		else
			error_message "The command 'mgmt_cli login' failed with this message: $message"
			exit 1
		fi

		if [ $READ_ATTEMPTS -ge 3 ]; then
			error_message "Invalid administrator credentials"
			exit 1
		fi
	else
		SESSION_ID=$($ECHO "$TEST_SESSION" | jq -r '.sid')
		$MGMT_CLI logout --session-id $SESSION_ID --port $PORT >/dev/null 2>&1
	fi
done

heavy_op_message

if [ $IS_MDS -eq 1 ]; then
	CURRENT_CMA=""

	if [ "$FWDIR" = "$MDSDIR" ] ; then
		$ECHO "The script is running in the MDS context."
		$ECHO "The script will handle all Domains."
	else
		CURRENT_CMA=$($MDSVERUTIL CMANameByFwDir -d $FWDIR)

		if [ -z "$CURRENT_CMA" ]; then
			error_handling_logout 1 "Failed to determine the Domain context."
			$ECHO "You must run the script from the MDS context (run the 'mdsenv' command)."
			$ECHO ""
			exit 1
		fi

		$ECHO "The script is running in the context of this Domain: \"$CURRENT_CMA\"."
		$ECHO "The script will handle only this Domain."
	fi
	$ECHO ""
fi

if [ "$RENEW_CERTIFICATES" -eq 0 ]; then
	CERTIFICATES_LIST=""
	if [ $IS_MDS -eq 1 ]; then
		$PRINTF "$MDS_FORMAT\n" "Days to Expiration" "Gateway Name" "Domain Server Name" \
			"Created on" "Expires on" "Type" "Status" 
	else
		$PRINTF "$MGMT_FORMAT\n" "Days to Expiration" "Gateway Name" "Created On" "Expires On" "Type" "Status" 
	fi
fi

CERTIFICATE_COUNT=0
CERTIFICATES_TO_RENEW=0
SUCCESSFULLY_RENEWED=0
FAILED_TO_RENEW=0
FAILED_TO_RENEW_EXTERNAL_CERT=0
FAILED_TO_RENEW_OTHER_CMA_CERT=0
handle_query_batch_results "show-gateways-and-servers" "-u $USERNAME -p $PASSWORD --port $PORT --format json"
if [ -z "$BATCH_OBJECTS" ]; then
	error_message "No output returned for the query for Gateways and Servers. Exiting..."
	exit 1
fi
GWS_AND_SERVERS_OUTPUT="$BATCH_OBJECTS"

if [ $IS_MDS -eq 1 ]; then
	source /opt/CPshared/5.0/tmp/.CPprofile.sh
	if [ -z "$CURRENT_CMA" ]; then
		mdsenv
		handle_all_cmas
	else
		handle_cma_by_name "$CURRENT_CMA"
	fi
else
	handle_single_cma "" ""
fi

if [ "$RENEW_CERTIFICATES" -eq 0 ]; then
	#Sort by Security Gateway name and remove duplicates, then sort by expiration date, in the ascending order.
	$ECHO -ne "$CERTIFICATES_LIST" | $SORT -u -k 2 | $SORT -k 1n
	$ECHO ""
	$ECHO "Number of certificates that matched the search criteria: $CERTIFICATE_COUNT"
	$ECHO ""

	if [ ! -z "$OUTPUT_FORMAT" ]; then
		if [ ! -f "$OUTPUT_FILE" ] || [ "$CERTIFICATE_COUNT" -le 0 ]; then
			$ECHO "Output file was not created."
			$ECHO ""
		elif [ ! -z "$OUTPUT_ERROR" ]; then
			$ECHO "Encountered errors while saving the output file."
			$ECHO "The output file may be incomplete."
			$ECHO "The output file is:"
			$ECHO "$OUTPUT_FILE"
			$ECHO ""
		else
			$ECHO "The output file is:"
			$ECHO "$OUTPUT_FILE"
			$ECHO ""
		fi
	fi
fi

if [ "$RENEW_CERTIFICATES" -eq 1 ] && [ "$CERTIFICATES_TO_RENEW" -ge 1 ]; then
	$ECHO ""
	$ECHO -e "Number of certificates - attempted to renew:\t $CERTIFICATES_TO_RENEW"
	if [ "$FAILED_TO_RENEW_EXTERNAL_CERT" -ge 1 ] || [ "$FAILED_TO_RENEW_OTHER_CMA_CERT" -ge 1 ]; then
		$ECHO -e "Number of certificates - *skipped* renewing:"
		$ECHO -e " --External CA Certificates:\t\t\t $FAILED_TO_RENEW_EXTERNAL_CERT"
		$ECHO -e " --Non-local Domain Server Certificates:\t $FAILED_TO_RENEW_OTHER_CMA_CERT"
	fi
	if [ "$FAILED_TO_RENEW" -ge 1 ]; then
		$ECHO -e "Number of certificates - *failed* to renew:\t $FAILED_TO_RENEW"
	fi
	if [ $SUCCESSFULLY_RENEWED -ge 1 ];then
		$ECHO -e "Number of certificates - successfully renewed:\t $SUCCESSFULLY_RENEWED"
		$ECHO ""
		$ECHO "----------------------------------------"
		$ECHO "*Important*:"
		$ECHO "----------------------------------------"
		$ECHO "(1) Certificates are issued with the date of *yesterday* to avoid timezone issues."
		$ECHO ""
		$ECHO "(2) You must install Access Control policy on all renewed Security Gateways."
		$ECHO "----------------------------------------"
		$ECHO ""
	fi
fi

if [ "$RENEW_CERTIFICATES" -eq 1 ] && [ "$CERTIFICATES_TO_RENEW" -eq 0 ]; then
	$ECHO -e "Number of certificates - attempted to renew:\t 0"
	$ECHO ""
fi

if [ -e "last_reply.txt" ]; then
	$RM last_reply.txt >/dev/null 2>&1
fi

if [ -e $COMMANDS_FILE ]; then
	$RM $COMMANDS_FILE >/dev/null 2>&1
fi
