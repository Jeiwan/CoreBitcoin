// Oleg Andreev <oleganza@gmail.com>

#import "BTCTransaction.h"
#import "BTCTransactionInput.h"
#import "BTCTransactionOutput.h"
#import "BTCProtocolSerialization.h"
#import "BTCData.h"
#import "BTCScript.h"
#import "BTCErrors.h"
#import "BTCHashID.h"

NSData* BTCTransactionHashFromID(NSString* txid) {
    return BTCHashFromID(txid);
}

NSString* BTCTransactionIDFromHash(NSData* txhash) {
    return BTCIDFromHash(txhash);
}

@interface BTCTransaction ()
@end

@implementation BTCTransaction

- (id) init {
    if (self = [super init]) {
        // init default values
        _version = BTCTransactionCurrentVersion;
        _lockTime = 0;
        _inputs = @[];
        _outputs = @[];
        _blockHeight = 0;
        _blockDate = nil;
        _confirmations = NSNotFound;
        _fee = -1;
        _inputsAmount = -1;
    }
    return self;
}

// Parses tx from data buffer.
- (id) initWithData:(NSData*)data {
    if (self = [self init]) {
        if (![self parseData:data]) return nil;
    }
    return self;
}

// Parses tx from hex string.
- (id) initWithHex:(NSString*)hex {
    return [self initWithData:BTCDataFromHex(hex)];
}

// Parses input stream (useful when parsing many transactions from a single source, e.g. a block).
- (id) initWithStream:(NSInputStream*)stream {
    if (self = [self init]) {
        if (![self parseStream:stream]) return nil;
    }
    return self;
}

// Constructs transaction from dictionary representation
- (id) initWithDictionary:(NSDictionary*)dictionary {
    if (self = [self init]) {
        _version = (uint32_t)[dictionary[@"ver"] unsignedIntegerValue];
        _lockTime = (uint32_t)[dictionary[@"lock_time"] unsignedIntegerValue];
        
        NSMutableArray* ins = [NSMutableArray array];
        for (id dict in dictionary[@"in"]) {
            BTCTransactionInput* txin = [[BTCTransactionInput alloc] initWithDictionary:dict];
            if (!txin) return nil;
            [ins addObject:txin];
        }
        _inputs = ins;
        
        NSMutableArray* outs = [NSMutableArray array];
        for (id dict in dictionary[@"out"]) {
            BTCTransactionOutput* txout = [[BTCTransactionOutput alloc] initWithDictionary:dict];
            if (!txout) return nil;
            [outs addObject:txout];
        }
        _outputs = outs;
    }
    return self;
}

// Returns a dictionary representation suitable for encoding in JSON or Plist.
- (NSDictionary*) dictionaryRepresentation {
    return self.dictionary;
}

- (NSDictionary*) dictionary {
    return @{
      @"hash":      self.transactionID,
      @"ver":       @(_version),
      @"vin_sz":    @(_inputs.count),
      @"vout_sz":   @(_outputs.count),
      @"lock_time": @(_lockTime),
      @"size":      @(self.data.length),
      @"in":        [_inputs valueForKey:@"dictionary"],
      @"out":       [_outputs valueForKey:@"dictionary"],
    };
}


#pragma mark - NSObject



- (BOOL) isEqual:(BTCTransaction*)object {
    if (![object isKindOfClass:[BTCTransaction class]]) return NO;
    return [object.transactionHash isEqual:self.transactionHash];
}

- (NSUInteger) hash {
    if (self.transactionHash.length >= sizeof(NSUInteger)) {
        // Interpret first bytes as a hash value
        return *((NSUInteger*)self.transactionHash.bytes);
    } else {
        return 0;
    }
}

- (id) copyWithZone:(NSZone *)zone {
    BTCTransaction* tx = [[BTCTransaction alloc] init];
    tx->_inputs = [[NSArray alloc] initWithArray:self.inputs copyItems:YES]; // so each element is copied individually
    tx->_outputs = [[NSArray alloc] initWithArray:self.outputs copyItems:YES]; // so each element is copied individually
    for (BTCTransactionInput* txin in tx.inputs) {
        txin.transaction = self;
    }
    for (BTCTransactionOutput* txout in tx.outputs) {
        txout.transaction = self;
    }
    tx.version = self.version;
    tx.lockTime = self.lockTime;

    // Copy informational properties as is.
    tx.blockHash     = [_blockHash copy];
    tx.blockHeight   = _blockHeight;
    tx.blockDate     = _blockDate;
    tx.confirmations = _confirmations;
    tx.userInfo      = _userInfo;

    return tx;
}



#pragma mark - Properties


- (NSData*) transactionHash {
    return BTCHash256(self.data);
}

- (NSString*) displayTransactionHash { // deprecated
    return self.transactionID;
}

- (NSString*) transactionID {
    return BTCIDFromHash(self.transactionHash);
}

- (NSString*) blockID {
    return BTCIDFromHash(self.blockHash);
}

- (void) setBlockID:(NSString *)blockID {
    self.blockHash = BTCHashFromID(blockID);
}

- (NSData*) data {
    return [self computePayload:true];
}

- (NSString*) hex {
    return BTCHexFromData(self.data);
}

- (NSData*) computePayload:(Boolean)includeWitness {
    NSMutableData* payload = [NSMutableData data];
    
    // 4-byte version
    uint32_t ver = _version;
    [payload appendBytes:&ver length:4];

    if (includeWitness){
        // 1-byte marker
        uint8_t marker = 0x00;
        [payload appendBytes:&marker length:1];
        
        // 1-byte flag (0x01 - always segwit)
        uint8_t flag = 0x01;
        [payload appendBytes:&flag length:1];
    }
    
    // varint with number of inputs
    [payload appendData:[BTCProtocolSerialization dataForVarInt:_inputs.count]];
    
    // input payloads
    for (BTCTransactionInput* input in _inputs) {
        [payload appendData:input.data];
    }
    
    // varint with number of outputs
    [payload appendData:[BTCProtocolSerialization dataForVarInt:_outputs.count]];
    
    // output payloads
    for (BTCTransactionOutput* output in _outputs) {
        [payload appendData:output.data];
    }
    
    if (includeWitness){
        for (BTCTransactionInput* input in _inputs) {
            [payload appendData:[BTCProtocolSerialization dataForVarInt:input.witness.count]];
            
            for(NSData* witnessPiece in input.witness) {
                [payload appendData:[BTCProtocolSerialization dataForVarString:witnessPiece]];
            }
        }
    }

    // 4-byte lock_time
    uint32_t lt = _lockTime;
    [payload appendBytes:&lt length:4];
    
    return payload;
}

- (NSUInteger) weight {
    return self.baseSize * 3 + self.data.length;
}

- (NSUInteger) baseSize {
    return [self computePayload:false].length;
}

- (NSUInteger) virtualSize {
    return (int)ceil((double)self.weight / 4.0);
}


#pragma mark - Methods


// Adds input script
- (void) addInput:(BTCTransactionInput*)input {
    if (!input) return;
    [self linkInput:input];
    _inputs = [_inputs arrayByAddingObject:input];
}

- (void) linkInput:(BTCTransactionInput*)input {
    if (!(input.transaction == nil || input.transaction == self)) {
        @throw [NSException exceptionWithName:@"BTCTransaction consistency error!" reason:@"Can't add an input to a transaction when it references another transaction." userInfo:nil];
        return;
    }
    input.transaction = self;
}

// Adds output script
- (void) addOutput:(BTCTransactionOutput*)output {
    if (!output) return;
    [self linkOutput:output];
    _outputs = [_outputs arrayByAddingObject:output];
}

- (void) linkOutput:(BTCTransactionOutput*)output {
    if (!(output.transaction == nil || output.transaction == self)) {
        @throw [NSException exceptionWithName:@"BTCTransaction consistency error!" reason:@"Can't add an output to a transaction when it references another transaction." userInfo:nil];
        return;
    }
    output.index = BTCTransactionOutputIndexUnknown; // reset to be recomputed lazily later
    output.transactionHash = nil; // can't be reliably set here because transaction may get updated.
    output.transaction = self;
}

- (void) setInputs:(NSArray *)inputs {
    [self removeAllInputs];
    for (BTCTransactionInput* txin in inputs) {
        [self addInput:txin];
    }
}

- (void) setOutputs:(NSArray *)outputs {
    [self removeAllOutputs];
    for (BTCTransactionOutput* txout in outputs) {
        [self addOutput:txout];
    }
}

- (void) removeAllInputs {
    for (BTCTransactionInput* txin in _inputs) {
        txin.transaction = nil;
    }
    _inputs = @[];
}

- (void) removeAllOutputs {
    for (BTCTransactionOutput* txout in _outputs) {
        txout.transaction = nil;
    }
    _outputs = @[];
}

- (BOOL) isCoinbase {
    // Coinbase transaction has one input and it must be coinbase.
    return (_inputs.count == 1 && [(BTCTransactionInput*)_inputs[0] isCoinbase]);
}


#pragma mark - Serialization and parsing



- (BOOL) parseData:(NSData*)data {
    if (!data) return NO;
    NSInputStream* stream = [NSInputStream inputStreamWithData:data];
    [stream open];
    BOOL result = [self parseStream:stream];
    [stream close];
    return result;
}

- (BOOL) parseStream:(NSInputStream*)stream {
    if (!stream) return NO;
    if (stream.streamStatus == NSStreamStatusClosed) return NO;
    if (stream.streamStatus == NSStreamStatusNotOpen) return NO;
    
    if ([stream read:(uint8_t*)&_version maxLength:sizeof(_version)] != sizeof(_version)) return NO;
    
    uint8_t marker;
    if ([stream read:(uint8_t*)&marker maxLength:sizeof(marker)] != sizeof(marker)) return NO;
    
    uint8_t flag;
    if ([stream read:(uint8_t*)&flag maxLength:sizeof(flag)] != sizeof(flag)) return NO;
    
    {
        uint64_t inputsCount = 0;
        if ([BTCProtocolSerialization readVarInt:&inputsCount fromStream:stream] == 0) return NO;
        
        NSMutableArray* ins = [NSMutableArray array];
        for (uint64_t i = 0; i < inputsCount; i++)
        {
            BTCTransactionInput* input = [[BTCTransactionInput alloc] initWithStream:stream];
            if (!input) return NO;
            [self linkInput:input];
            [ins addObject:input];
        }
        _inputs = ins;
    }

    {
        uint64_t outputsCount = 0;
        if ([BTCProtocolSerialization readVarInt:&outputsCount fromStream:stream] == 0) return NO;
            
        NSMutableArray* outs = [NSMutableArray array];
        for (uint64_t i = 0; i < outputsCount; i++)
        {
            BTCTransactionOutput* output = [[BTCTransactionOutput alloc] initWithStream:stream];
            if (!output) return NO;
            [self linkOutput:output];
            [outs addObject:output];
        }
        _outputs = outs;
    }
    
    
    {
        NSMutableArray* witnessedInputs = [NSMutableArray array];
        
        for (uint64_t i = 0; i < _inputs.count; i++)
        {
            uint64_t witnessPartsCount = 0;
            if ([BTCProtocolSerialization readVarInt:&witnessPartsCount fromStream:stream] == 0) return NO;

            NSMutableArray* witnessData = [NSMutableArray array];
            for (uint64_t j = 0; j < witnessPartsCount; j++)
            {
                NSData* witnessPiece = [BTCProtocolSerialization readVarStringFromStream:stream];
                if (!witnessPiece) return NO;

                [witnessData addObject:witnessPiece];
            }
            
            BTCTransactionInput* input = [_inputs objectAtIndex:i];
            [input setWitness:witnessData];
            [witnessedInputs addObject:input];
        }
        
        _inputs = witnessedInputs;
    }
    
    if ([stream read:(uint8_t*)&_lockTime maxLength:sizeof(_lockTime)] != sizeof(_lockTime)) return NO;
    
    return YES;
}


#pragma mark - Signing a transaction



// Hash for signing a transaction.
// You should supply the output script of the previous transaction, desired hash type and input index in this transaction.
- (NSData*) signatureHashForScript:(BTCScript*)subscript inputIndex:(uint32_t)inputIndex hashType:(BTCSignatureHashType)hashType error:(NSError**)errorOut {
    // Create a temporary copy of the transaction to apply modifications to it.
    BTCTransaction* tx = [self copy];
    
    // We may have a scriptmachine instantiated without a transaction (for testing),
    // but it should not use signature checks then.
    if (!tx || inputIndex == 0xFFFFFFFF) {
        if (errorOut) *errorOut = [NSError errorWithDomain:BTCErrorDomain
                                                      code:BTCErrorScriptError
                                                  userInfo:@{NSLocalizedDescriptionKey: NSLocalizedString(@"Transaction and valid input index must be provided for signature verification.", @"")}];
        return nil;
    }
    
    // Note: BitcoinQT returns a 256-bit little-endian number 1 in such case, but it does not matter
    // because it would crash before that in CScriptCheck::operator()(). We normally won't enter this condition
    // if script machine is instantiated with initWithTransaction:inputIndex:, but if it was just -init-ed, it's better to check.
    if (inputIndex >= tx.inputs.count) {
        if (errorOut) *errorOut = [NSError errorWithDomain:BTCErrorDomain
                                                      code:BTCErrorScriptError
                                                  userInfo:@{NSLocalizedDescriptionKey:[NSString stringWithFormat:
                                                     NSLocalizedString(@"Input index is out of bounds for transaction: %d >= %d.", @""),
                                                                                        (int)inputIndex, (int)tx.inputs.count]}];
        return nil;
    }
    
    // Previous outputs and sequences
    NSMutableData* prevouts = [NSMutableData data];
    NSMutableData* sequence = [NSMutableData data];
    for(BTCTransactionInput* input in _inputs) {
        [prevouts appendData:[input previousHash]];
        
        uint32_t previousIndex = [input previousIndex];
        [prevouts appendBytes:&previousIndex length:4];

        uint32_t seq = [input sequence];
        [sequence appendBytes:&seq length:4];
    }
    
    // New outputs
    NSMutableData* nextouts = [NSMutableData data];
    for(BTCTransactionOutput* output in _outputs) {
        [nextouts appendData:output.data];
    }
    
    // Outpoint
    NSMutableData* outpointData = [NSMutableData data];
    BTCTransactionInput* outpoint = [_inputs objectAtIndex:inputIndex];
    
    [outpointData appendData:[outpoint previousHash]];
    
    uint32_t outpointIndex = [outpoint previousIndex];
    [outpointData appendBytes:&outpointIndex length:sizeof(outpointIndex)];
    
    int64_t amount = (int64_t)[outpoint value];
    uint32_t nSequence = [outpoint sequence];

    // Hashing...
    NSData* hashPrevouts = BTCHash256(prevouts);
    NSData* hashSequence = BTCHash256(sequence);
    NSData* hashOutputs = BTCHash256(nextouts);
    
    // Preimage
    NSMutableData* preimage = [NSMutableData data];
    
    [preimage appendBytes:&_version length:sizeof(_version)];
    [preimage appendData:hashPrevouts];
    [preimage appendData:hashSequence];
    [preimage appendData:outpointData];
    [preimage appendData:[subscript scriptCode]];
    [preimage appendBytes:&amount length:sizeof(amount)];
    [preimage appendBytes:&nSequence length:sizeof(nSequence)];
    [preimage appendData:hashOutputs];
    [preimage appendBytes:&_lockTime length:sizeof(_lockTime)];
    
    // Important: we have to hash transaction together with its hash type.
    // Hash type is appended as little endian uint32 unlike 1-byte suffix of the signature.
    uint32_t hashType32 = OSSwapHostToLittleInt32((uint32_t)hashType);
    [preimage appendBytes:&hashType32 length:sizeof(hashType32)];

    NSData* hash = BTCHash256(preimage);
    
//    NSLog(@"\n----------------------\n");
//    NSLog(@"TX: %@", BTCHexFromData(fulldata));
//    NSLog(@"TX SUBSCRIPT: %@ (%@)", BTCHexFromData(subscript.data), subscript);
//    NSLog(@"TX HASH: %@", BTCHexFromData(hash));
//    NSLog(@"TX PLIST: %@", tx.dictionary);
    
    return hash;
}






#pragma mark - Amounts and fee



@synthesize fee=_fee;
@synthesize inputsAmount=_inputsAmount;

- (void) setFee:(BTCAmount)fee {
    _fee = fee;
    _inputsAmount = -1; // will be computed from fee or inputs.map(&:value)
}

- (BTCAmount) fee {
    if (_fee != -1) {
        return _fee;
    }

    BTCAmount ia = self.inputsAmount;
    if (ia != -1) {
        return ia - self.outputsAmount;
    }

    return -1;
}

- (void) setInputsAmount:(BTCAmount)inputsAmount {
    _inputsAmount = inputsAmount;
    _fee = -1; // will be computed from inputs and outputs amount on the fly.
}

- (BTCAmount) inputsAmount {
    if (_inputsAmount != -1) {
        return _inputsAmount;
    }

    if (_fee != -1) {
        return _fee + self.outputsAmount;
    }

    // Try to figure the total amount from amounts on inputs.
    // If all of them are non-nil, we have a valid amount.

    BTCAmount total = 0;
    for (BTCTransactionInput* txin in self.inputs) {
        BTCAmount v = txin.value;
        if (v == -1) {
            return -1;
        }
        total += v;
    }
    return total;
}

- (BTCAmount) outputsAmount {
    BTCAmount a = 0;
    for (BTCTransactionOutput* txout in self.outputs) {
        a += txout.value;
    }
    return a;
}






#pragma mark - Fees



// Computes estimated fee for this tx size using default fee rate.
// @see BTCTransactionDefaultFeeRate.
- (BTCAmount) estimatedFee {
    return [self estimatedFeeWithRate:BTCTransactionDefaultFeeRate];
}

// Computes estimated fee for this tx size using specified fee rate (satoshis per 1000 bytes).
- (BTCAmount) estimatedFeeWithRate:(BTCAmount)feePerK {
    return [BTCTransaction estimateFeeForSize:self.data.length feeRate:feePerK];
}

// Computes estimated fee for the given tx size using specified fee rate (satoshis per 1000 bytes).
+ (BTCAmount) estimateFeeForSize:(NSInteger)txsize feeRate:(BTCAmount)feePerK {
    if (feePerK <= 0) return 0;
    BTCAmount fee = 0;
    while (txsize > 0) { // add fee rate for each (even incomplete) 1K byte chunk
        txsize -= 1000;
        fee += feePerK;
    }
    return fee;
}




// TO BE REVIEWED:



// Minimum base fee to send a transaction.
+ (BTCAmount) minimumFee {
    NSNumber* n = [[NSUserDefaults standardUserDefaults] objectForKey:@"BTCTransactionMinimumFee"];
    if (!n) return 10000;
    return (BTCAmount)[n longLongValue];
}

+ (void) setMinimumFee:(BTCAmount)fee {
    fee = MIN(fee, BTC_MAX_MONEY);
    [[NSUserDefaults standardUserDefaults] setObject:[NSNumber numberWithLongLong:fee] forKey:@"BTCTransactionMinimumFee"];
}

// Minimum base fee to relay a transaction.
+ (BTCAmount) minimumRelayFee {
    NSNumber* n = [[NSUserDefaults standardUserDefaults] objectForKey:@"BTCTransactionMinimumRelayFee"];
    if (!n) return 10000;
    return (BTCAmount)[n longLongValue];
}

+ (void) setMinimumRelayFee:(BTCAmount)fee {
    fee = MIN(fee, BTC_MAX_MONEY);
    [[NSUserDefaults standardUserDefaults] setObject:[NSNumber numberWithLongLong:fee] forKey:@"BTCTransactionMinimumRelayFee"];
}


// Minimum fee to relay the transaction
- (BTCAmount) minimumRelayFee {
    return [self minimumFeeForSending:NO];
}

// Minimum fee to send the transaction
- (BTCAmount) minimumSendFee {
    return [self minimumFeeForSending:YES];
}

- (BTCAmount) minimumFeeForSending:(BOOL)sending {
    // See also CTransaction::GetMinFee in BitcoinQT and calculate_minimum_fee in bitcoin-ruby
    
    // BitcoinQT calculates min fee based on current block size, but it's unused and constant value is used today instead.
    NSUInteger baseBlockSize = 1000;
    // BitcoinQT has some complex formulas to determine when we shouldn't allow free txs. To be done later.
    BOOL allowFree = YES;
    
    BTCAmount baseFee = sending ? [BTCTransaction minimumFee] : [BTCTransaction minimumRelayFee];
    NSUInteger txSize = self.data.length;
    NSUInteger newBlockSize = baseBlockSize + txSize;
    BTCAmount minFee = (1 + txSize / 1000) * baseFee;
    
    if (allowFree) {
        if (newBlockSize == 1) {
            // Transactions under 10K are free
            // (about 4500 BTC if made of 50 BTC inputs)
            if (txSize < 10000)
                minFee = 0;
        } else {
            // Free transaction area
            if (newBlockSize < 27000)
                minFee = 0;
        }
    }
    
    // To limit dust spam, require base fee if any output is less than 0.01
    if (minFee < baseFee) {
        for (BTCTransactionOutput* txout in _outputs) {
            if (txout.value < BTCCent) {
                minFee = baseFee;
                break;
            }
        }
    }
    
    // Raise the price as the block approaches full
    if (baseBlockSize != 1 && newBlockSize >= BTC_MAX_BLOCK_SIZE_GEN/2) {
        if (newBlockSize >= BTC_MAX_BLOCK_SIZE_GEN)
            return BTC_MAX_MONEY;
        minFee *= BTC_MAX_BLOCK_SIZE_GEN / (BTC_MAX_BLOCK_SIZE_GEN - newBlockSize);
    }
    
    if (minFee < 0 || minFee > BTC_MAX_MONEY) minFee = BTC_MAX_MONEY;
    
    return minFee;
}



@end
