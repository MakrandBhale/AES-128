public class AES {

    String hexPlainText, hexKey;
    private boolean logging = true;
    private final String message, key;
    private enum Operation {ENCRYPTION, DECRYPTION}
    private AES(String plainText, String key){
        this.message = plainText;
        this.key = key;
    }

    public String encrypt(){
        this.hexPlainText = stringToHex(this.message);
        this.hexKey = stringToHex(key);

        String[][] messageMatrix = createMatrix(this.hexPlainText);
        String[][] keyMatrix = createMatrix(this.hexKey);
        log("Encrypting message");
        log("Message HEX: " + this.hexPlainText);
        log("Key HEX: " + this.hexKey);

        /* generating keys for all 11 rounds; i.e. 1st initial round and 10 repeated Rounds */
        String[][] keySchedule = generateIntermediateKeys(keyMatrix);
        /* initial round 1 */
        int round = 1;
        addRoundKey(messageMatrix, getKeyMatrixForRound(round, keySchedule));
        log("\nAfter Initial Round of XOR: ");
        log(messageMatrix);
        /* looping over 10 rounds */
        for (int i = 1; i <= 10; i++) {
            ++round;
            subBytes(messageMatrix);
            shiftRows(messageMatrix);
            if(i != 10 )
            mixColumns(messageMatrix, Operation.ENCRYPTION);
            String[][] keyForCurrentRound = getKeyMatrixForRound(round, keySchedule);
            addRoundKey(messageMatrix, keyForCurrentRound);
            log("\n---- Round " + (round-1) + " ----");
            log("Message: \t\t\t Key: ");
            log(messageMatrix, keyForCurrentRound);

        }
        String encryptedMessage = matrixToText(messageMatrix);
        log("\n\nOriginal message: " + this.message);
        log("Original key: " + this.key);
        log("Message HEX: " + this.hexPlainText);

        log("Final encrypted message: " + encryptedMessage);
        return encryptedMessage;
    }


    public String decrypt() {
        this.hexPlainText = this.message; /* no conversion to hex because the encrypted message is already in hex form.*/
        this.hexKey = stringToHex(this.key);
        String[][] messageMatrix = createMatrix(this.hexPlainText);
        String[][] keySchedule = generateIntermediateKeys(createMatrix(this.hexKey));

        log("\n\n---- Decrypting Message ----");
        log("Received Message: " + this.hexPlainText);
        log("Key: " + this.hexKey);
        /* initial round 1*/
        int round = 10; /* inversing the round keys*/

        for(int i = round; i >= 1; i--){
            String[][] keyForCurrentRound = getInverseKeyForRound(round, keySchedule);
            addRoundKey(messageMatrix, keyForCurrentRound);
            if(i != 10) {
                mixColumns(messageMatrix, Operation.DECRYPTION);
            }
            invShiftRows(messageMatrix);
            invSubBytes(messageMatrix);
            log("\n---- Round " + (round-1) + " ----");
            log("Message: \t\t\t\t Key: ");
            log(messageMatrix, keyForCurrentRound);
            --round;
        }
        log("\nAfter final round of XOR: ");
        addRoundKey(messageMatrix, getKeyMatrixForRound(1, keySchedule));
        log(messageMatrix);
        String decryptedMessage = matrixToText(messageMatrix);
        log("Decrypted Message: " + decryptedMessage);
        log("Original Message: " +  hexToString(decryptedMessage.replaceAll(" ", "")));
        return decryptedMessage;
    }



    private void invShiftRows(String[][] messageMatrix) {
        /*right wards shifting of rows according to row number*/
        /* shifting rows according column */
        for (int i = 1; i < messageMatrix.length; i++) {
            int k = i;
            while(k > 0){
                String temp = messageMatrix[i][3];
                /* left shifting */
                for (int j = 2; j >= 0; j--) {
                    messageMatrix[i][j+1] = messageMatrix[i][j];
                }
                messageMatrix[i][0] = temp;
                k--;
            }
        }
    }

    private void invSubBytes(String[][] message){
        for(int i = 0; i < message.length; i++){
            for(int j  = 0; j < message.length; j++){
                /* using inverse SubBoxes for decryption */
                message[i][j] = getSBoxSubstitute(message[i][j], LookupTables.iSBox);
            }
        }
    }

    private void mixColumns(String[][] messageMatrix, Operation operation){
        String[] vector;
        String[] mixedColumn = new String[messageMatrix.length];
        for(int col = 0; col < messageMatrix.length; col++){
            for(int row = 0, x = 0; row < messageMatrix.length; row++, x++){
                mixedColumn[x] = messageMatrix[row][col];
            }
            vector = vectorMultiplication(mixedColumn, operation);
            for(int row = 0, x = 0; row < messageMatrix.length; row++, x++) {
                messageMatrix[row][col] = vector[x];
            }
        }
    }


    private String[] vectorMultiplication(String[] block, Operation operation) {
        String[] res = new String[block.length];
        int x = 0;
        if(operation == Operation.ENCRYPTION){
            for(char[] row : LookupTables.galoisTable){
                int temp = 0;
                for(int i = 0; i < row.length; i++){
                    /* Depending on the operation choose how to multiply.*/
                    temp = temp ^ (bitMultiply(hexToInt(block[i]), row[i]));
                }
                res[x] = intToHex(temp);
                x++;
            }
        } else {
            for(char[] row : LookupTables.inverseGalois){
                int temp = 0;
                for(int i = 0; i < row.length; i++){
                    /* Depending on the operation choose how to multiply.*/
                    temp = temp ^ (invBitMultiply(hexToInt(block[i]), row[i]));
                }
                res[x] = intToHex(temp);
                x++;
            }
        }

        return res;
    }


    private int invBitMultiply(int num, int a){
        int row = num/16;
        int col = num%16;
        if (a == 9) {
            return LookupTables.mc9[row][col];
        } else if (a == 0xb) {
            return LookupTables.mc11[row][col];
        } else if (a == 0xd) {
            return LookupTables.mc13[row][col];
        } else if (a == 0xe) {
            return LookupTables.mc14[row][col];
        }
        return 0;
    }
    private int bitMultiply(int num, int a){
        /* function to perform bit level multiplication */
        int row = num/16;
        int col = num%16;
        if(a == 1) {
            return num;
        } else if(a == 2){
            return LookupTables.mc2[row][col];
        } else if (a == 3) {
            return LookupTables.mc3[row][col];
        }
        return 0;
    }
    private void shiftRows(String[][] messageMatrix) {
        /* left shifting rows according to row number */
        for (int i = 1; i < messageMatrix.length; i++) {
            int k = i;
            while(k > 0){
                String temp = messageMatrix[i][0];
                /* left shifting */
                for (int j = 1; j < messageMatrix[i].length; j++) {
                    messageMatrix[i][j-1] = messageMatrix[i][j];
                }
                messageMatrix[i][3] = temp;
                k--;
            }
        }
    }

    private void subBytes(String[][] message){
        for(int i = 0; i < message.length; i++){
            for(int j  = 0; j < message.length; j++){
                message[i][j] = getSBoxSubstitute(message[i][j], LookupTables.sBox);
            }
        }
    }

    private String[][] getInverseKeyForRound(int round, String[][] keyMatrix) {
        String[][] key = new String[4][4];
        int currentRoundColumn = (round * 4);
        for(int col = currentRoundColumn, col1 = 0; col < currentRoundColumn + 4; col++, col1++) {
             /*getting 4x4 block of key according to the running round from
             * 4 x 44 key matrix.
             * FOR DECRYPTING: getting key from end and move to start.*
             * */

            for(int row = 0, row1 = 0; row < 4; row++, row1++){
                key[row1][col1] = keyMatrix[row][col];
            }
        }
        return key;
    }


    private String[][] getKeyMatrixForRound(int round, String[][] keyMatrix) {
        String[][] key = new String[4][4];
        int col1 = 0;
        for(int col = (round - 1)*4; col < ((round - 1) * 4) + 4; col++, col1++) {
            /*getting 4x4 block of key according to the running round from
            * 4 x 44 key matrix.
            * */
            for(int row = 0, row1 = 0; row < 4; row++, row1++){
                key[row1][col1] = keyMatrix[row][col];
            }
        }
        return key;
    }

    private void addRoundKey(String[][] message, String[][] key){
        for(int col = 0; col < 4; col++) {
            /*getting 4x4 block of key according to the running round from
             * 4 x 44 key matrix.
             * */
            for(int row = 0; row < 4; row++){
                message[row][col] = intToHex(hexToInt(message[row][col]) ^ hexToInt(key[row][col]));
            }
        }
    }

    private String[][] generateIntermediateKeys(String[][] keyMatrix) {
        String[][] keys = new String[4][44]; /* 4x4 matrix for 11 rounds i.e. 4 x 44 matrix*/
        /* add given key as it is in the keys matrix, because for first round the key is same.*/
        for(int i = 0 ; i < keyMatrix.length; i++){
            for (int j = 0; j < keyMatrix[0].length; j++) {
                keys[i][j] = keyMatrix[i][j];
            }
        }
        /*generating remaining keys*/
        int round = 0;
        String[] word;
        for(int j = 4; j < 44; j++){
            if(j%4 == 0) {
                round++;
                /* for every first column of 4x44 matrix*/
                String[] columnVector = extractColumnVector(keys, j - 1); /* consider it as a column vector [4x1]*/
                upRotate(columnVector);
                /* Encrypting and Decrypting is in-affected  thus not using inverse sBox for decrypting;*/
                pickFromSBox(columnVector);
                String[] fourPosPrevVector = extractColumnVector(keys, j-4);
                columnVector = xorVector(columnVector, fourPosPrevVector);
                columnVector = xorVector(columnVector, getRConVector(round));
                word = columnVector.clone();
            } else {
                /* for every other position */
                String[] prevVector = extractColumnVector(keys, j -1 );
                String[] fourPosPrevVector = extractColumnVector(keys, j-4);
                word = xorVector(prevVector, fourPosPrevVector);
            }

            for (int i = 0; i < 4; i++) {
                keys[i][j] = word[i];
            }
        }

        return keys;
    }

    private String[] getRConVector(int round) {
        /* get rCon for specific round.*/
        String[] stringVector = new String[4];
        for (int i = 0; i < 4; i++) {
            stringVector[i] = Integer.toHexString(LookupTables.rCon[round][i]);
        }
        return stringVector;
    }


    private String[] xorVector(String[] a, String[] b){
        String[] res = new String[a.length];
        for (int i = 0; i < a.length; i++) {
            res[i] = intToHex(hexToInt(a[i]) ^ hexToInt(b[i])); /* hexString -> int then XOR then back to hexString*/
        }
        return res;
    }

    private void pickFromSBox(String[] columnVector) {
        /* substitution according to the sBox*/
        for(int i = 0 ; i < columnVector.length; i++){
            columnVector[i] = getSBoxSubstitute(columnVector[i], LookupTables.sBox);
        }
    }

    private void upRotate(String[] columnVector) {
        /* rotating array one place upwards */
        String temp = columnVector[0];
        int i = 1;
        while (i < 4) {
            columnVector[i-1] = columnVector[i];
            i++;
        }
        columnVector[3] = temp;
    }

    private String[] extractColumnVector(String[][] matrix, int index){
        /* function to get a single column from the matrix. */
        String[] vector = new String[4];
        for(int j = 0; j < 4; j++){
            vector[j] = matrix[j][index];
        }
        return vector;
    }

    private String getSBoxSubstitute(String hex, final char[] sBox){
        int index = Integer.parseInt(hex, 16);
        char b = sBox[index];
        String temp = Integer.toHexString(b);
        return "0".repeat(2 - temp.length()) + temp;
    }

    private String[][] createMatrix(String hexMessage) {
        String[][] matrix = new String[4][4];
        int k = 0;

        for(int i = 0; i < 4; i = i + 1){
            for(int j = 0; j < 4; j++){
                matrix[j][i] =  hexMessage.substring(k, k + 2);
                k = k+2;
            }
        }
        return matrix;
    }


    public static AES init(String plainText, String key) throws IllegalArgumentException {
        if(key.length() > 16){
           throw  new IllegalArgumentException("Key can not be greater than 16 characters");
        }

        if(plainText.length() != 32) {
            if(plainText.length() > 16)
                throw new IllegalArgumentException("Plaintext can not be greater than 16 characters");
        }
        return new AES(plainText, key);
    }

    public static AES init(String plainText, String key, boolean logging) throws IllegalArgumentException {
        AES aes = AES.init(plainText, key);
        aes.logging = logging;
        return aes;
    }


    private int hexToInt(String s){
        return Integer.parseInt(s, 16);
    }

    private String intToHex(int num) {
        String hex = Integer.toHexString(num);
        if(hex.length() < 2) {
            hex = "0".repeat(2 - hex.length()) + hex;
        }
        return hex;
    }
    private String stringToHex(String string){
        int MAX_STRING_SIZE = 16;
        string = string + " ".repeat(MAX_STRING_SIZE - string.length());
        StringBuilder sb = new StringBuilder();
        for(char c : string.toCharArray()){
            sb.append(Integer.toHexString(c));
        }
        return sb.toString();
    }


    private void log(String[][] matrix) {
        if(!this.logging) return;
        for (String[] strings : matrix) {
            for (int j = 0; j < matrix[0].length; j++) {
                System.out.print(strings[j] + "  ");
            }
            System.out.println();
        }
    }

    private void log(String[][] matrix, String [][] key) {
        if(!this.logging) return;
        for (int i = 0; i < matrix.length;i++) {
            for (int j = 0; j < matrix[0].length; j++) {
                System.out.print(matrix[i][j] + "  ");
            }
            System.out.print(" |\t");

            for (int j = 0; j < matrix[0].length; j++) {
                System.out.print(key[i][j] + "  ");
            }

            System.out.println();
        }
    }

    private String matrixToText(String[][] matrix){
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < matrix.length; i++) {
            for (int j = 0; j < matrix[0].length; j++) {
                sb.append(matrix[j][i]).append(" ");
            }
        }
        return sb.toString();
    }

    private void log(String message){
        if(this.logging)
            System.out.println(message);
    }

    private String hexToString(String hexString){
        StringBuilder sb = new StringBuilder();
        for(int i = 0; i < hexString.length(); i = i+ 2){
            char c = (char) hexToInt(hexString.substring(i, i+2));
            sb.append(c);
        }
        return sb.toString();
    }

}
