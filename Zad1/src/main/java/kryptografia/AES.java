package kryptografia;

public class AES {
    static int[][] sBox = {
            {0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76},
            {0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0},
            {0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15},
            {0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75},
            {0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84},
            {0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf},
            {0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8},
            {0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2},
            {0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73},
            {0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb},
            {0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79},
            {0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08},
            {0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a},
            {0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e},
            {0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf},
            {0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16}};

    static int[][] inv_sbox = new int[][]{
            {0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb},
            {0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb},
            {0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e},
            {0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25},
            {0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92},
            {0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84},
            {0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06},
            {0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b},
            {0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73},
            {0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e},
            {0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b},
            {0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4},
            {0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f},
            {0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef},
            {0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61},
            {0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d}
    };

    byte[][] keyWords; // 44 words of 32(4bytes) bits
    byte[][] keyWordsReversed; // for decryption
    byte[] entranceKey;
    private static final char[] HEX_ARRAY = "0123456789ABCDEF".toCharArray();


    public AES(byte[] originalKey) throws Exception {
        if (originalKey.length != 16) {
            throw new Exception("key has wrong length!");
        }
        this.entranceKey = originalKey;
        this.keyWords = generateSubKeys(entranceKey);
        this.keyWordsReversed = generateReversedSubKeys(keyWords);
    }

    public byte[][] generateReversedSubKeys(byte[][] keyWords) {
        int k = 0;
        byte[][] tmp = new byte[44][4];
        for (int i = 10; i >= 0; i--) {
            for (int j = 0; j < 4; j++) {
                tmp[k] = keyWords[i * 4 + j];
                k++;
            }
        }
        return tmp;
    }

    public byte[] encode(byte[] message) {

        int wholeBlocksCount = message.length / 16;
        int charactersToEncodeCount;
        if (wholeBlocksCount == 0) {
            charactersToEncodeCount = 16;
        } else if (message.length % 16 != 0) {
            charactersToEncodeCount = (wholeBlocksCount + 1) * 16;
        } else {
            charactersToEncodeCount = wholeBlocksCount * 16;
        }

        byte[] result = new byte[charactersToEncodeCount];
        byte[] temp = new byte[charactersToEncodeCount];
        byte[] blok = new byte[16];

        for (int i = 0; i < charactersToEncodeCount; ++i) {
            if (i < message.length) {
                temp[i] = message[i];
            } else {
                temp[i] = 0;
            }
        }

        int i = 0;
        while (i < temp.length) {
            for (int j = 0; j < 16; ++j) {
                blok[j] = temp[i++];
            }

            blok = this.encrypt(blok);
            System.arraycopy(blok, 0, result, i - 16, blok.length);
        }

        return result;
    }

    public byte[] decode(byte[] message) {
        if (message.length % 16 != 0) {
            return null;
        }

        int blocksCount = message.length / 16;
        byte[][] dataAsBlocks = new byte[blocksCount][16];

        int i = 0;
        for (int block = 0; block < blocksCount; block++) {
            for (int b = 0; b < 16; b++) {
                dataAsBlocks[block][b] = message[i];
                i++;
            }
        }


        i = 0;

        byte[] tmp = new byte[message.length];
        for (int block = 0; block < blocksCount; block++) {
            for (int b = 0; b < 16; b++) {
                tmp[i] = decrypt(dataAsBlocks[block])[b];
                i++;
            }
        }

        int zeros = 0;
        for (int j = 0; j < 16; j++) {
            if (tmp[tmp.length - (j + 1)] == '\0') {
                zeros++;
            } else {
                break;
            }
        }

        byte[] output = new byte[blocksCount * 16 - zeros];
        System.arraycopy(tmp, 0, output, 0, blocksCount * 16 - zeros);


        return output;
    }

    public byte[] encrypt(byte[] state) {
        byte[] tmp = state;

        tmp = addKey(tmp, 0);

        tmp = subBytes(tmp);
        tmp = shiftRows(tmp);
        tmp = mixColumns(tmp);
        tmp = addKey(tmp, 1);

        for (int i = 2; i < 10; i++) {
            tmp = subBytes(tmp);
            tmp = shiftRows(tmp);
            tmp = mixColumns(tmp);
            tmp = addKey(tmp, i);
        }

        tmp = subBytes(tmp);
        tmp = shiftRows(tmp);
        tmp = addKey(tmp, 10);

        return tmp;
    }


    public byte[] decrypt(byte[] state) {
        byte[] tmp = state;


        // inverse round 10:
        tmp = addKey(tmp, 10);
        tmp = shiftRowsReversed(tmp);
        tmp = subBytesReversed(tmp);

        for (int i = 9; i > 1; i--) {
            tmp = addKey(tmp, i);
            tmp = inverseMixColumns(tmp);
            tmp = shiftRowsReversed(tmp);
            tmp = subBytesReversed(tmp);
        }

        tmp = addKey(tmp, 1);
        tmp = inverseMixColumns(tmp);
        tmp = shiftRowsReversed(tmp);
        tmp = subBytesReversed(tmp);
        tmp = addKey(tmp, 0);

        return tmp;
    }


    public byte[][] generateSubKeys(byte[] keyInput) {
        int j = 0;
        byte[][] tmp = new byte[44][4];
        for (int i = 0; i < 4; i++) {
            for (int k = 0; k < 4; k++) {
                tmp[i][k] = keyInput[j];
            }
        }

        for (int round = 1; round <= 10; round++) {
            tmp[4 * round] = xorWords(tmp[4 * round - 4], g(tmp[4 * round - 1], round));
            tmp[4 * round + 1] = xorWords(tmp[4 * round], tmp[4 * round - 3]);
            tmp[4 * round + 2] = xorWords(tmp[4 * round + 1], tmp[4 * round - 2]);
            tmp[4 * round + 2] = xorWords(tmp[4 * round + 2], tmp[4 * round - 1]);
        }

        return tmp;
    }
    static byte translate(byte b) {
        int x = (b & 0b11110000) >> 4;
        int y = b & 0b00001111;
        return (byte) sBox[x][y];
    }

    static byte translateReverse(byte b) {
        int x = (b & 0b11110000) >> 4;
        int y = b & 0b00001111;
        return (byte) inv_sbox[x][y];
    }

    public byte[] xorWords(byte[] word1, byte[] word2) {
        if (word1.length == word2.length) {
            byte[] tmp = new byte[word1.length];
            for (int i = 0; i < word1.length; i++) {
                tmp[i] = (byte) (word1[i] ^ word2[i]);
            }
            return tmp;
        } else {
            return null;
        }
    }

    static public byte fMul(byte a, byte b) {
        int tmp = polynomialMultiplication(a, b);
        return polynomialModuloDivision(tmp);
    }

    static public int polynomialMultiplication(byte a, byte b) {
        int result = 0;
        int aTmp;
        int bTmp;
        for (int i = 0; i < 8; i++) {
            for (int j = 0; j < 8; j++) {
                aTmp = a & (1 << i);
                bTmp = b & (1 << j);
                if (aTmp != 0 && bTmp != 0) {
                    result ^= (1 << (i + j));
                }
            }
        }
        return result;
    }
    static public byte polynomialModuloDivision(int a) {
        while (a > 255) {
            int shift = getFirstBit(a) - 8;
            a = a ^ (0b100011011 << shift);
        }
        return (byte) a;
    }

    static public int getFirstBit(int a) {
        int first = 0;
        for (int i = 0; i < 32; i++) {
            if ((a & (1 << i)) != 0) {
                first = i;
            }
        }
        return first;
    }

    public static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i + 1), 16));
        }
        return data;
    }

    public static String bytesToHex(byte[] bytes) {
        char[] hexChars = new char[bytes.length * 2];
        for (int j = 0; j < bytes.length; j++) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = HEX_ARRAY[v >>> 4];
            hexChars[j * 2 + 1] = HEX_ARRAY[v & 0x0F];
        }
        return new String(hexChars);
    }
    public byte[] g(byte[] word, int round) {
        byte[] tmp = shiftArrayLeft(word, 1);
        for (int i = 0; i < 4; i++) {
            tmp[i] = translate(tmp[i]);
        }

        byte RC = polynomialModuloDivision((byte) (0b1 << (round - 1)));
        tmp[0] ^= RC;

        return tmp;
    }

    public byte[] addKey(byte[] state, int round) {
        byte[] tmp = new byte[state.length];
        int start = round * 4;
        int end = start + 4;
        int k = 0;
        for (int i = start; i < end; i++) {
            for (int j = 0; j < 4; j++) {
                tmp[k] = (byte) (state[k] ^ keyWords[i][j]);
                k++;
            }
        }
        return tmp;
    }


    private byte[] subBytes(byte[] state) {
        byte[] tmp = new byte[state.length];
        for (int i = 0; i < state.length; i++) {
            tmp[i] = translate(state[i]);
        }
        return tmp;
    }

    private byte[] subBytesReversed(byte[] state) {
        byte[] tmp = new byte[state.length];
        for (int i = 0; i < state.length; i++) {
            tmp[i] = translateReverse(state[i]);
        }
        return tmp;
    }

    public byte[] shiftRows(byte[] state) {
        byte[][] tmp = new byte[4][4];
        int k = 0;
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                tmp[j][i] = state[k];
                k++;
            }
        }
        shiftArrayLeft(tmp[1], 1);
        shiftArrayLeft(tmp[2], 2);
        shiftArrayLeft(tmp[3], 3);
        byte[] newState = new byte[16];
        k = 0;
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                newState[k] = tmp[j][i];
                k++;
            }
        }

        return newState;
    }


    public byte[] shiftArrayLeft(byte[] array, int step) {
        for (int i = 0; i < step; i++) {
            int j;
            byte first;
            first = array[0];

            for (j = 1; j < array.length; j++) {
                array[j - 1] = array[j];
            }
            array[array.length - 1] = first;
        }
        return array;
    }


    public byte[] mixColumns(byte[] state) {

        byte[][] columns = new byte[4][4];
        int k = 0;
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                columns[i][j] = state[k];
                k++;
            }
        }
        for (int i = 0; i < 4; i++) {
            columns[i] = multiplySingleColumn(columns[i]);
        }
        byte[] tmp = new byte[16];
        k = 0;
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                tmp[k] = columns[i][j];
                k++;
            }
        }
        return tmp;

    }
    public byte[] multiplySingleColumn(byte[] column) {
        byte[] c = new byte[4];
        c[0] = (byte) (fMul((byte) 0x02, column[0]) ^ fMul((byte) 0x03, column[1]) ^ column[2] ^ column[3]);
        c[1] = (byte) (column[0] ^ fMul((byte) 0x02, column[1]) ^ fMul((byte) 0x03, column[2]) ^ column[3]);
        c[2] = (byte) (column[0] ^ column[1] ^ fMul((byte) 0x02, column[2]) ^ fMul((byte) 0x03, column[3]));
        c[3] = (byte) (fMul((byte) 0x03, column[0]) ^ column[1] ^ column[2] ^fMul((byte) 0x02, column[3]));
        return c;
    }

    public byte[] inverseMixColumns(byte[] state) {

        byte[][] columns = new byte[4][4];
        int k = 0;
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                columns[i][j] = state[k];
                k++;
            }
        }
        for (int i = 0; i < 4; i++) {
            columns[i] = multiplySingleColumnReversed(columns[i]);
        }
        byte[] tmp = new byte[16];
        k = 0;
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                tmp[k] = columns[i][j];
                k++;
            }
        }
        return tmp;

    }

    public byte[] multiplySingleColumnReversed(byte[] column) {
        byte[] c = new byte[4];
        c[0] = (byte) (fMul((byte) 0x0E, column[0]) ^ fMul((byte) 0x0B, column[1]) ^ fMul((byte) 0x0D, column[2]) ^ fMul((byte) 0x09, column[3]));
        c[1] = (byte) (fMul((byte) 0x09, column[0]) ^ fMul((byte) 0x0E, column[1]) ^ fMul((byte) 0x0B, column[2]) ^ fMul((byte) 0x0D, column[3]));
        c[2] = (byte) (fMul((byte) 0x0D, column[0]) ^ fMul((byte) 0x09, column[1]) ^ fMul((byte) 0x0E, column[2]) ^ fMul((byte) 0x0B, column[3]));
        c[3] = (byte) (fMul((byte) 0x0B, column[0]) ^ fMul((byte) 0x0D, column[1]) ^ fMul((byte) 0x09, column[2]) ^ fMul((byte) 0x0E, column[3]));
        return c;
    }

    public byte[] shiftRowsReversed(byte[] state) {
        byte[][] tmp = new byte[4][4];
        int k = 0;
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                tmp[j][i] = state[k];
                k++;
            }
        }

        shiftArrayRight(tmp[1], 1);
        shiftArrayRight(tmp[2], 2);
        shiftArrayRight(tmp[3], 3);

        byte[] newState = new byte[16];
        k = 0;
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                newState[k] = tmp[j][i];
                k++;
            }
        }

        return newState;
    }

    byte[] shiftArrayRight(byte[] array, int step) {
        for (int i = 0; i < step; i++) {
            int j;
            byte last;
            last = array[array.length - 1];
            for (j = array.length - 2; j >= 0; j--) {
                array[j + 1] = array[j];
            }
            array[0] = last;
        }
        return array;
    }


    public byte[][] getKeyWords() {
        return keyWords;
    }

    public byte[][] getKeyWordsReversed() {
        return keyWordsReversed;
    }

    public byte[] getEntranceKey() {
        return entranceKey;
    }


}
