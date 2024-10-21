import json
from binascii import unhexlify
import hashlib
from ecdsa import SigningKey, SECP256k1

def double_sha256(data):
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()

def parse_der_signature(signature):
    if signature[0] != 0x30:
        raise ValueError("Invalid signature format")
    
    r_start = 4
    r_length = signature[3]
    r = int.from_bytes(signature[r_start:r_start+r_length], 'big')
    
    s_start = r_start + r_length + 2
    s_length = signature[s_start - 1]
    s = int.from_bytes(signature[s_start:s_start+s_length], 'big')
    
    return r, s

def serialize_input(tx, input_index, subscript, sighash_type=1):
    # This is a simplified version and may not cover all edge cases
    s = tx['version'].to_bytes(4, 'little')
    s += bytes([len(tx['inputs'])])
    
    for i, inp in enumerate(tx['inputs']):
        s += bytes.fromhex(inp['txid'])[::-1]
        s += inp['output'].to_bytes(4, 'little')
        
        if i == input_index:
            s += bytes([len(subscript)]) + subscript
        else:
            s += b'\x00'
        
        s += inp['sequence'].to_bytes(4, 'little')
    
    s += bytes([len(tx['outputs'])])
    for out in tx['outputs']:
        s += out['value'].to_bytes(8, 'little')
        script = bytes.fromhex(out['pkscript'])
        s += bytes([len(script)]) + script
    
    s += tx['locktime'].to_bytes(4, 'little')
    s += sighash_type.to_bytes(4, 'little')
    
    return s

def calculate_z(tx, input_index, subscript, sighash_type=1):
    serialized = serialize_input(tx, input_index, subscript, sighash_type)
    return int.from_bytes(double_sha256(serialized), 'big')

def extract_transaction_info(tx_data):
    tx_data = tx_data.strip()
    if tx_data.startswith("'''") and tx_data.endswith("'''"):
        tx_data = tx_data[3:-3]
    
    try:
        tx = json.loads(tx_data)
    except json.JSONDecodeError as e:
        print(f"Error decoding JSON: {e}")
        return
    
    for i, input_data in enumerate(tx['inputs']):
        print(f"Input {i + 1}:")
        
        sigscript = unhexlify(input_data['sigscript'])
        
        try:
            sig_length = sigscript[0]
            signature = sigscript[1:sig_length+1]
            
            if len(sigscript) > sig_length + 1:
                pubkey_length = sigscript[sig_length+1]
                public_key = sigscript[sig_length+2:sig_length+2+pubkey_length]
                print(f"  Public Key: {public_key.hex()}")
            else:
                print("  Public Key: Not available in sigscript")
            
            print(f"  Signature: {signature.hex()}")
            
            r, s = parse_der_signature(signature)
            print(f"  r value (decimal): {r}")
            print(f"  r value (hex): {hex(r)}")
            print(f"  s value (decimal): {s}")
            print(f"  s value (hex): {hex(s)}")
            
            # Calculate z value
            subscript = bytes.fromhex(input_data['pkscript'])
            z = calculate_z(tx, i, subscript)
            print(f"  z value (H(m)) (decimal): {z}")
            print(f"  z value (H(m)) (hex): {hex(z)}")
            
        except IndexError:
            print("  Unable to parse sigscript: format not as expected")
        except ValueError as e:
            print(f"  Error parsing signature: {str(e)}")
        
        print()

# Use the function with your transaction data
transaction_data = '''
{
  "txid": "d76641afb4d0cc648a2f74db09f86ea264498341c49434a933ba8eef9352ab6f",
  "size": 224,
  "version": 1,
  "locktime": 0,
  "fee": 0,
  "inputs": [
    {
      "coinbase": false,
      "txid": "0a855d267a1451407953b93c6b29118f00f4da90f98dcdca59a8fee2148906f2",
      "output": 0,
      "sigscript": "483045022043784344e1e0cb498c1d73b4cee970fb0f9adf38b7891d0b1310fdb9cbc23929022100a734f4e97a05bd169a9f0eb296fc841fa57f8753db09869f8f6f8cc1232616d4014104d6597d465408e6e11264c116dd98b539740e802dc756d7eb88741696e20dfe7d3588695d2e7ad23cbf0aa056d42afada63036d66a1d9b97070dd6bc0c87ceb0d",
      "sequence": 4294967295,
      "pkscript": "76a91412d5a845f2b212ce0c3bd65a4035881d9219090e88ac",
      "value": 300000000000,
      "address": "12ib7dApVFvg82TXKycWBNpN8kFyiAN1dr",
      "witness": []
    }
  ],
  "outputs": [
    {
      "address": "15BxdjCWWqL6dVUuREVUxaXfjX37RaVDTd",
      "pkscript": "76a9142df31a60b02cce392822c9a87198753578ef7de888ac",
      "value": 300000000000,
      "spent": true,
      "spender": {
        "txid": "3695ffd3814ff143ca0b800578767006f877f1f01e238edcbeaff405480cbb53",
        "input": 4
      }
    }
  ],
  "block": {
    "height": 59027,
    "position": 1
  },
  "deleted": false,
  "time": 1275489785,
  "rbf": false,
  "weight": 896
}
'''

extract_transaction_info(transaction_data)
