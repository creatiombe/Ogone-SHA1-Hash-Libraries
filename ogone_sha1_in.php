<?php

/**
 * Ogone SHA1 In
 * 
 * Simple library to add key:value pairs of fields
 * used in the communication with Ogone.
 * This lib only allows fields needed for the SHA1
 * hash.
 * The collection of fields can simply be converted
 * into a SHA1 encrypted hash.
 * 
 * @author Koos van Egmond | Cream Internetbureau
 */

class OgoneSHA1In {
	
	/**
	 * Fields allowed/needed in the SHA1 hash
	 * @var Array
	 */
	protected $_allowedFields = array(
		'ACCEPTANCE', 'ACCEPTURL', 'ADDMATCH', 'ADDRMATCH', 'AIAGIATA',
		'AIAIRNAME', 'AIAIRTAX', 'AIBOOKIND', 'AICARRIER', 'AICHDET',
		'AICLASS', 'AICONJTI', 'AIDEPTCODE', 'AIDESTCITY', 'AIDESTCITYL',
		'AIEXTRAPASNAME', 'AIEYCD', 'AIFLDATE', 'AIFLNUM', 'AIGLNUM',
		'AIINVOICE', 'AIIRST', 'AIORCITY', 'AIORCITYL', 'AIPASNAME',
		'AIPROJNUM', 'AISTOPOV', 'AITIDATE', 'AITINUM', 'AITINUML', 'AITYPCH',
		'AIVATAMNT', 'AIVATAPPL', 'ALIAS', 'ALIASOPERATION', 'ALIASUSAGE',
		'ALLOWCORRECTION', 'AMOUNT', 'AMOUNT', 'AMOUNTHTVA', 'AMOUNTTVA',
		'BACKURL', 'BATCHID', 'BGCOLOR', 'BLVERNUM', 'BRAND', 'BRANDVISUAL',
		'BUTTONBGCOLOR', 'BUTTONTXTCOLOR', 'CANCELURL', 'CARDNO', 'CATALOGURL',
		'CAVV_3D', 'CAVVALGORITHM_3D', 'CERTID', 'CHECK_AAV', 'CIVILITY', 'CN',
		'COM', 'COMPLUS', 'COSTCENTER', 'COSTCODE', 'CREDITCODE', 'CUID',
		'CURRENCY', 'CVC', 'CVCFLAG', 'DATA', 'DATATYPE', 'DATEIN', 'DATEOUT',
		'DECLINEURL', 'DEVICE', 'DISCOUNTRATE', 'DISPLAYMODE', 'ECI', 'ECI_3D',
		'ECOM_BILLTO_POSTAL_CITY', 'ECOM_BILLTO_POSTAL_COUNTRYCODE',
		'ECOM_BILLTO_POSTAL_NAME_FIRST', 'ECOM_BILLTO_POSTAL_NAME_LAST',
		'ECOM_BILLTO_POSTAL_POSTALCODE', 'ECOM_BILLTO_POSTAL_STREET_LINE1',
		'ECOM_BILLTO_POSTAL_STREET_LINE2', 'ECOM_BILLTO_POSTAL_STREET_NUMBER',
		'ECOM_CONSUMERID', 'ECOM_CONSUMER_GENDER', 'ECOM_CONSUMEROGID',
		'ECOM_CONSUMERORDERID', 'ECOM_CONSUMERUSERALIAS',
		'ECOM_CONSUMERUSERPWD', 'ECOM_CONSUMERUSERID',
		'ECOM_PAYMENT_CARD_EXPDATE_MONTH', 'ECOM_PAYMENT_CARD_EXPDATE_YEAR',
		'ECOM_PAYMENT_CARD_NAME', 'ECOM_PAYMENT_CARD_VERIFICATION',
		'ECOM_SHIPTO_COMPANY', 'ECOM_SHIPTO_DOB', 'ECOM_SHIPTO_ONLINE_EMAIL',
		'ECOM_SHIPTO_POSTAL_CITY', 'ECOM_SHIPTO_POSTAL_COUNTRYCODE',
		'ECOM_SHIPTO_POSTAL_NAME_FIRST', 'ECOM_SHIPTO_POSTAL_NAME_LAST',
		'ECOM_SHIPTO_POSTAL_NAME_PREFIX', 'ECOM_SHIPTO_POSTAL_POSTALCODE',
		'ECOM_SHIPTO_POSTAL_STREET_LINE1', 'ECOM_SHIPTO_POSTAL_STREET_LINE2',
		'ECOM_SHIPTO_POSTAL_STREET_NUMBER', 'ECOM_SHIPTO_TELECOM_FAX_NUMBER',
		'ECOM_SHIPTO_TELECOM_PHONE_NUMBER', 'ECOM_SHIPTO_TVA', 'ED', 'EMAIL',
		'EXCEPTIONURL', 'EXCLPMLIST', 'EXECUTIONDATE', 'FACEXCL', 'FACTOTAL',
		'FIRSTCALL', 'FLAG3D', 'FONTTYPE', 'FORCECODE1', 'FORCECODE2',
		'FORCECODEHASH', 'FORCEPROCESS', 'FORCETP', 'GENERIC_BL',
		'GIROPAY_ACCOUNT_NUMBER', 'GIROPAY_BLZ', 'GIROPAY_OWNER_NAME',
		'GLOBORDERID', 'GUID', 'HDFONTTYPE', 'HDTBLBGCOLOR', 'HDTBLTXTCOLOR',
		'HEIGHTFRAME', 'HOMEURL', 'HTTP_ACCEPT', 'HTTP_USER_AGENT',
		'INCLUDE_BIN', 'INCLUDE_COUNTRIES', 'INVDATE', 'INVDISCOUNT',
		'INVLEVEL', 'INVORDERID', 'ISSUERID', 'IST_MOBILE', 'ITEM_COUNT',
		'LANGUAGE', 'LEVEL1AUTHCPC', 'LIDEXCL',
		'LIMITCLIENTSCRIPTUSAGE', 'LINE_REF', 'LINE_REF1', 'LINE_REF2',
		'LINE_REF3', 'LINE_REF4', 'LINE_REF5', 'LINE_REF6', 'LIST_BIN',
		'LIST_COUNTRIES', 'LOGO', 'MAXITEMQUANT', 'MERCHANTID', 'MODE',
		'MTIME', 'MVER', 'NETAMOUNT', 'OPERATION', 'ORDERID', 'ORDERSHIPCOST',
		'ORDERSHIPTAX', 'ORDERSHIPTAXCODE', 'ORIG', 'OR_INVORDERID',
		'OR_ORDERID', 'OWNERADDRESS', 'OWNERADDRESS2', 'OWNERCTY',
		'OWNERTELNO', 'OWNERTOWN', 'OWNERZIP', 'PAIDAMOUNT', 'PARAMPLUS',
		'PARAMVAR', 'PAYID', 'PAYMETHOD', 'PM', 'PMLIST', 'PMLISTPMLISTTYPE',
		'PMLISTTYPE', 'PMLISTTYPEPMLIST', 'PMTYPE', 'POPUP', 'POST', 'PSPID',
		'PSWD', 'REF', 'REFER', 'REFID', 'REFKIND', 'REF_CUSTOMERID',
		'REF_CUSTOMERREF', 'REGISTRED', 'REMOTE_ADDR', 'REQGENFIELDS',
		'RTIMEOUT', 'RTIMEOUTREQUESTEDTIMEOUT', 'SCORINGCLIENT', 'SETT_BATCH',
		'SID', 'STATUS_3D', 'SUBSCRIPTION_ID', 'SUB_AM', 'SUB_AMOUNT',
		'SUB_COM', 'SUB_COMMENT', 'SUB_CUR', 'SUB_ENDDATE', 'SUB_ORDERID',
		'SUB_PERIOD_MOMENT', 'SUB_PERIOD_MOMENT_M', 'SUB_PERIOD_MOMENT_WW',
		'SUB_PERIOD_NUMBER', 'SUB_PERIOD_NUMBER_D', 'SUB_PERIOD_NUMBER_M',
		'SUB_PERIOD_NUMBER_WW', 'SUB_PERIOD_UNIT', 'SUB_STARTDATE',
		'SUB_STATUS', 'TAAL', 'TAXINCLUDED', 'TBLBGCOLOR', 'TBLTXTCOLOR',
		'TID', 'TITLE', 'TOTALAMOUNT', 'TP', 'TRACK2', 'TXTBADDR2', 'TXTCOLOR',
		'TXTOKEN', 'TXTOKENTXTOKENPAYPAL', 'TYPE_COUNTRY',
		'UCAF_AUTHENTICATION_DATA', 'UCAF_PAYMENT_CARD_CVC2',
		'UCAF_PAYMENT_CARD_EXPDATE_MONTH', 'UCAF_PAYMENT_CARD_EXPDATE_YEAR',
		'UCAF_PAYMENT_CARD_NUMBER', 'USERID', 'USERTYPE', 'VERSION',
		'WBTU_MSISDN', 'WBTU_ORDERID', 'WEIGHTUNIT', 'WIN3DS', 'WITHROO'
	);
	
	/**
	 * List of fields that are incremental
	 * @var Array
	 */
	protected $_incrementalAllowedFields = array(
		'ITEMATTRIBUTES', 'ITEMCATEGORY', 'ITEMCOMMENTS', 'ITEMDESC',
		'ITEMDISCOUNT', 'ITEMID', 'ITEMNAME', 'ITEMPRICE', 'ITEMQUANT',
		'ITEMQUANTORIG', 'ITEMUNITOFMEASURE', 'ITEMVAT', 'ITEMVATCODE',
		'ITEMWEIGHT'
	);
	
	/**
	 * List of all the fields currently added
	 * @var Array
	 */
	protected $_fields = array();
	
	/**
	 * Variable with the secret hash to use in the
	 * salted hash
	 * @var String
	 */
	protected $_secretHash;
	
	/**
	 * Method to add a field to the fieldlist.
	 * This method checks if the field is allowed and
	 * is not empty. Otherwise, it will not be added
	 * @param String $key
	 * @param String $val
	 */
	public function addField($key, $val) {
		
		// Set correct data
		$key = strtoupper(trim($key));
		$val = trim($val);
		
		// Skip if the field is empty
		if (empty($val)) return;
		
		// Remove the dot from the amount
		if ($key == 'AMOUNT') {
			$val = str_replace('.', '', $val);
		}
		
		// Check if the field is needed
		if (in_array($key, $this->_allowedFields)) {

			$this->_fields[$key] = $val;
			return false;
		}
		
		// Check if the field is incremental otherwise
		$numberlessKey = preg_replace('/\d/', '', $key);
		if (in_array($numberlessKey, $this->_incrementalAllowedFields)) {
			
			$this->_fields[$key] = $val;
			return false;
		}
	}
	
	/**
	 * Function to batch add fields with the use
	 * off @see self::addField
	 * @param Array $array
	 */
	public function addFields($array) {
		
		// Check if the value is actually a filled array
		if (!is_array($array) || empty($array)) return;
		
		// Loop through the values and add fields
		foreach ($array as $key => $val) {
			
			$this->addField($key, $val);
		}
	}
	
	/**
	 * Method to set the current secret hash
	 * @param String $hash
	 */
	public function setHash($hash) {
		
		$this->_secretHash = trim($hash);
	}
	
	/**
	 * Method to get the current secret hash
	 * @return String
	 */
	public function getHash() {
		
		return $this->_secretHash;
	}
	
	/**
	 * Method to return the hash.
	 * This method will order the list of fields
	 * alphabetical, create a string with the fields
	 * as key:value appended by the secret hash.
	 * Finally it returns the generated string as a SHA1
	 * hash.
	 * @return String
	 */
	public function toHash() {
		
		// Start empty string
		$string = '';
		
		// Order the fields array alphabetical
		ksort($this->_fields);
		
		// Loop through the data and generate a string
		// with key:value pairs, separated by the hash salt
		foreach ($this->_fields as $key => $val) {
			
			// Add the key:value pair
			$string .= sprintf('%s=%s%s', $key, $val, $this->getHash());
		}
		
		// SHA1 hash the string and return it
		return sha1($string);
	}
	
}