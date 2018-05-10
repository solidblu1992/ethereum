pragma solidity ^0.4.22;

library UTXO {
    //Represents an input unspent transaction output (candidate for spending)
    struct Input {
        uint256[2] pub_key;
        uint256[2] value;
    }
    
    //Represents an output unspent transaction output (new stealth transaction output)
    struct Output {
        uint256[2] pub_key;
        uint256[2] value;
        uint256[2] dhe_point;
        uint256[3] encrypted_data;
    }
    
    //Create UTXO.Input[] struct aray from uint256 array
	//Used so that public functions can deal with structures
    function DeserializeInputArray(uint256[] argsSerialized)
        internal pure returns (Input[] input_tx)
    {
        //Must at least specify length
        require(argsSerialized.length > 0);
        
        //Allocate array
        input_tx = new Input[](argsSerialized[0]);
        
        //Must have sufficient array size
        require(argsSerialized.length >= (1 + input_tx.length*4));
        
        //Fill in input_tx parameters
        uint256 i;
        uint256 index = 1;
        for (i = 0; i < input_tx.length; i++) {
            input_tx[i].pub_key = [argsSerialized[index], argsSerialized[index+1]];
            input_tx[i].value = [argsSerialized[index+2], argsSerialized[index+3]];
            index = index + 4;
        }
    }
	
	//Convert UTXO.Input[] into uint256 array
	//Used so that public functions can deal with structures
    function SerializeInputArray(Input[] input_tx)
        internal pure returns (uint256[] argsSerialized)
    {
		//Allocate data
		argsSerialized = new uint256[](1 + input_tx.length*4);
		argsSerialized[0] = input_tx.length;
		
		//Serialize
		uint256 i;
		uint256 index = 1;
		for (i = 0; i < input_tx.length; i++) {
			argsSerialized[index] = input_tx[i].pub_key[0];
			argsSerialized[index+1] = input_tx[i].pub_key[1];
			argsSerialized[index+2] = input_tx[i].value[0];
			argsSerialized[index+3] = input_tx[i].value[1];
			index = index + 4;
		}
    }
	
	//Create UTXO.Output[] struct aray from uint256 array
	//Used so that public functions can deal with structures
	function DeserializeOutputArray(uint256[] argsSerialized)
        internal pure returns (Output[] output_tx)
    {
		//Must at least specify length
        require(argsSerialized.length > 0);
        
        //Allocate array
        output_tx = new Output[](argsSerialized[0]);
        
        //Must have sufficient array size
        require(argsSerialized.length >= (1 + output_tx.length*9));
        
        //Fill in output_tx parameters
        uint256 i;
        uint256 index = 1;
        for (i = 0; i < output_tx.length; i++) {
            output_tx[i].pub_key = [argsSerialized[index], argsSerialized[index+1]];
            output_tx[i].value = [argsSerialized[index+2], argsSerialized[index+3]];
			output_tx[i].dhe_point = [argsSerialized[index+4], argsSerialized[index+5]];
			output_tx[i].encrypted_data = [argsSerialized[index+6], argsSerialized[index+7], argsSerialized[index+8]];
            index = index + 9;
        }
    }
	
	//Convert UTXO.Output[] into uint256 array
	//Used so that public functions can deal with structures
    function SerializeOutputArray(Output[] output_tx)
        internal pure returns (uint256[] argsSerialized)
    {
		//Allocate data
		argsSerialized = new uint256[](1 + output_tx.length*9);
		argsSerialized[0] = output_tx.length;
		
		//Serialize
		uint256 i;
		uint256 index = 1;
		for (i = 0; i < output_tx.length; i++) {
			argsSerialized[index] = output_tx[i].pub_key[0];
			argsSerialized[index+1] = output_tx[i].pub_key[1];
			argsSerialized[index+2] = output_tx[i].value[0];
			argsSerialized[index+3] = output_tx[i].value[1];
			argsSerialized[index+4] = output_tx[i].dhe_point[0];
			argsSerialized[index+5] = output_tx[i].dhe_point[1];
			argsSerialized[index+6] = output_tx[i].encrypted_data[0];
			argsSerialized[index+7] = output_tx[i].encrypted_data[1];
			argsSerialized[index+8] = output_tx[i].encrypted_data[2];
			index = index + 9;
		}
    }
    
    //Create UTXO.Input[] struct array from inputs
	//Used so that public functions can deal with structures
	function CreateInputArray(uint256[] input_pub_keys, uint256[] input_values)
		internal pure returns (Input[] input_tx)
	{
	    //Check input array lengths
	    require(input_pub_keys.length % 2 == 0);
	    require(input_values.length == input_pub_keys.length);
	    
	    //Create input_tx and output_tx
	    input_tx = new Input[](input_pub_keys.length / 2);
	    
	    uint256 i;
	    uint256 index;
	    for (i = 0; i < input_tx.length; i++) {
	        index = 2*i;
	        input_tx[i].pub_key[0] = input_pub_keys[index];
	        input_tx[i].pub_key[1] = input_pub_keys[index+1];
	        
	        input_tx[i].value[0] = input_values[index];
	        input_tx[i].value[1] = input_values[index+1];
	    }
	}
	
	//Create UTXO.Output[] struct array from inputs
	//Used so that public functions can deal with structures
	function CreateOutputArray(uint256[] output_pub_keys, uint256[] output_values, uint256[] output_dhe_points, uint256[] output_encrypted_data)
		internal pure returns (Output[] output_tx)
	{
		//Check output array lengths
	    require(output_pub_keys.length % 2 == 0);
	    require(output_values.length == output_pub_keys.length);
	    require(output_dhe_points.length == output_pub_keys.length);
	    require(output_encrypted_data.length == 3*(output_pub_keys.length / 2));
	    
	    //Create input_tx and output_tx
	    output_tx = new Output[](output_pub_keys.length / 2);
	    
	    uint256 i;
	    uint256 index;	    
	    for (i = 0; i < output_tx.length; i++) {
	        index = 2*i;
	        output_tx[i].pub_key[0] = output_pub_keys[index];
	        output_tx[i].pub_key[1] = output_pub_keys[index+1];
	        
	        output_tx[i].value[0] = output_values[index];
	        output_tx[i].value[1] = output_values[index+1];
	        
	        output_tx[i].dhe_point[0] = output_dhe_points[index];
	        output_tx[i].dhe_point[1] = output_dhe_points[index+1];
	        
	        index = 3*i;
	        output_tx[i].encrypted_data[0] = output_encrypted_data[index];
	        output_tx[i].encrypted_data[1] = output_encrypted_data[index+1];
	        output_tx[i].encrypted_data[2] = output_encrypted_data[index+2];
	    }
	}
	
	function EchoTestInput(uint256[] argsSerialized) public constant returns (uint256[]) {
	    return SerializeInputArray(DeserializeInputArray(argsSerialized));
	}
	
	function EchoTestOutput(uint256[] argsSerialized) public constant returns (uint256[]) {
	    return SerializeOutputArray(DeserializeOutputArray(argsSerialized));
	}
}