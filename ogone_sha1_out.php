<?php

/**
 * Ogone SHA1 Out
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

class OgoneSHA1Out {
	
	/**
	 * Fields allowed/needed in the SHA1 hash
	 * @var Array
	 */
	protected $_allowedFields = array(
		'AAVADDRESS', 'AAVCHECK', 'AAVZIP', 'ACCEPTANCE', 'ALIAS', 'AMOUNT',
		'BIN', 'BRAND', 'CARDNO', 'CCCTY', 'CN', 'COMPLUS', 'CREATION_STATUS',
		'CURRENCY', 'CVCCHECK', 'DCC_COMMPERCENTAGE', 'DCC_CONVAMOUNT',
		'DCC_CONVCCY', 'DCC_EXCHRATE', 'DCC_EXCHRATESOURCE', 'DCC_EXCHRATETS',
		'DCC_INDICATOR', 'DCC_MARGINPERCENTAGE', 'DCC_VALIDHOURS',
		'DIGESTCARDNO', 'ECI', 'ED', 'ENCCARDNO', 'IP', 'IPCTY',
		'NBREMAILUSAGE', 'NBRIPUSAGE', 'NBRIPUSAGE_ALLTX', 'NBRUSAGE',
		'NCERROR', 'ORDERID', 'PAYID', 'PM', 'SCO_CATEGORY', 'SCORING',
		'STATUS', 'SUBBRAND', 'SUBSCRIPTION_ID', 'TRXDATE', 'VC'
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
		
		// Check if the field is needed
		if (in_array($key, $this->_allowedFields)) {

			$this->_fields[$key] = $val;
			return false;
		}
	}
	
	/**
	 * Function to batch add fields with the use
	 * off @see self::addField
	 * @param Array $array
	 */
	public function addFields(array $array) {
		
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
		return strtoupper(sha1($string));
	}
	
}