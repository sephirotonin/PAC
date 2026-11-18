#include <stdio.h>
#include <stdint.h>
#include <math.h>
#include <string.h>

// aes s-box
static const uint8_t SBOX[256] = {
0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
};

static const uint8_t RCON[11] = {0x00,0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36};

static uint8_t GMUL2[256]; // Ergebnis mult. mit 2 in AES-Galois-Feld
static uint8_t GMUL3[256];

static int TABLES_READY = 0;

static void init_tables(void) { // einmalig; Vorbereitung Tabellen
    if (TABLES_READY) 
        return;

    for (int i = 0; i < 256; i++) {
        uint8_t value_times_2 = (uint8_t)((i << 1) ^ ((i & 0x80) ? 0x1b : 0));

        GMUL2[i] = value_times_2;
        GMUL3[i] = (uint8_t)(value_times_2 ^ i);
    }
    TABLES_READY = 1;
}


static void key_expansion(const uint8_t key[16], uint8_t round_keys[176]) { // 16 Bytes ursprüngl. Schlüssel; 176 Bytes für alle

    memcpy(round_keys, key, 16);

    int position = 16;
    int round = 1;

    uint8_t temp[4];

    while (position < 176) {
        memcpy(temp, round_keys + position - 4, 4); // letzte 4 Bytes kopieren

        if (position % 16 == 0) { // neuer RoundKey alle 16 Bytes
            uint8_t first = temp[0]; // RotWord; 1 pos

            temp[0] = temp[1];
            temp[1] = temp[2];
            temp[2] = temp[3];
            temp[3] = first;

            for (int i = 0; i < 4; i++) temp[i] = SBOX[temp[i]]; // SubWord; S-Box auf jedes byte 

            temp[0] ^= RCON[round++]; // Rundenkonstante
        }

        for (int i = 0; i < 4; i++) {
            round_keys[position] = (uint8_t)(round_keys[position - 16] ^ temp[i]);
            position++;
        }
    }
}


static void aes_encrypt(const uint8_t plaintext[16], const uint8_t round_keys[176], uint8_t ciphertext[16]) {
    uint8_t state[16];

    memcpy(state, plaintext, 16); // copy pt

    //AddRoundKey
    for (int i = 0; i < 16; i++) {
        state[i] ^= round_keys[i];
    }

    // AES-Runden:
    for (int round = 1; round <= 10; round++) {

        //SubBytes
        for (int i = 0; i < 16; i++) {
            state[i] = SBOX[state[i]];
        } 

        //ShiftRows
        uint8_t temp[16]; 
        memcpy(temp, state, 16);

        for (int column = 0; column < 4; column++){
            for (int row = 0; row < 4; row++) {
                state[row + 4*column] = temp[row + 4*((column + row) % 4)];
            }
        }
        
        //MixColumn
        if (round != 10) {       //ohne letzte Runde 
            for (int column = 0; column < 4; column++) {

                uint8_t a0=state[4*column];
                uint8_t a1=state[4*column+1];
                uint8_t a2=state[4*column+2];
                uint8_t a3=state[4*column+3];

                state[4*column] = GMUL2[a0] ^ GMUL3[a1] ^ a2 ^ a3;
                state[4*column + 1] = a0 ^ GMUL2[a1] ^ GMUL3[a2] ^ a3;
                state[4*column + 2] = a0 ^ a1 ^ GMUL2[a2] ^GMUL3[a3];
                state[4*column + 3] = GMUL3[a0] ^ a1 ^ a2 ^ GMUL2[a3];
            }
        }

        //AddRoundKey
        for (int i = 0; i < 16; i++) {
            state[i] ^= round_keys[16 * round + i];
        }
    }
    memcpy(ciphertext, state, 16);
}



// statistik
typedef struct {
    int count; // sample count; # Messwerte
    double mean; // durchschnitt
    double M2; // squared deviation sum (hilfswert für Varianz)
} Stats;

// Messwert hinzufügen
static void add_value(Stats *statistics, double val) {
    (*statistics).count++;
    double diff = val - (*statistics).mean; // abstand zu mean
    //update mean
    (*statistics).mean += diff / (*statistics).count;
    (*statistics).M2 += diff * (val - (*statistics).mean); //update variance
}

// variance berechnen
static double variance(Stats *statistics) {

    return (*statistics).M2 / ((*statistics).count - 1);
}



// t_value berechnen + Gruppen
static double t_test(Stats *a, Stats *b) {

    double variance_a = variance(a);
    double variance_b = variance(b);

    // denominator berechnen
    double denominator = sqrt(variance_a / (*a).count + variance_b / (*b).count);

    return ((*b).mean - (*a).mean) / denominator; // Unterschied zw. Mittelwerten
}

// round 2

#define NREF 11 // # referenzbytes für die Kollision

//pos refbytes in pt
static const int REF_BYTES[NREF] = {1, 3, 4, 6, 7, 8, 9, 11, 12, 13, 14};

// 64 für upper 6 k0
// 4 für lower 2 von k0
// 4 für lower 2 von k5
// 4 für lower 2 von k10
// 4 für lower 2 von k15
//64 * 4^4 = 16.384 kandidaten

void attack_round2(const uint8_t *plaintexts, const double *times, int n_traces, const int *deltas, double *t_values) {
    init_tables(); // aes

    // known key differences aus round1
    int delta_k2 = deltas[1];
    int delta_k5 = deltas[4];
    int delta_k10 = deltas[9];
    int delta_k15 = deltas[14];

    int res_idx = 0; // pos in Ergebnis-Array

    for (int guess = 0; guess < 64; guess++) { // teste die oberen 6 bits von k0 (64 Mögl.)

        int ref_top6[NREF];
        // obere 6 bits von ref-bytes berechnen
        for (int ref_pos = 0; ref_pos < NREF; ref_pos++) {

            ref_top6[ref_pos] = guess ^ deltas[REF_BYTES[ref_pos] - 1];
        }

        // test lower 2 bits of keybytes
        for (int key0_low2 = 0; key0_low2 < 4; key0_low2++)
        for (int key5_low2 = 0; key5_low2 < 4; key5_low2++)
        for (int key10_low2 = 0; key10_low2 < 4; key10_low2++)
        for (int key15_low2 = 0; key15_low2 < 4; key15_low2++) {
            // Schlüsselbytes zusammensetzen
            uint8_t k0  = (guess << 2) | key0_low2;
            uint8_t k5  = ((guess ^ delta_k5) << 2) | key5_low2;
            uint8_t k10 = ((guess ^ delta_k10) << 2) | key10_low2;
            uint8_t k15 = ((guess ^ delta_k15) << 2) | key15_low2;

            uint8_t k2 = (guess ^ delta_k2) << 2; //k2 oberer teil keybyte (6 bits)

            // group
            Stats collision[NREF] = {0};
            Stats no_collision[NREF] = {0};

            for (int trace = 0; trace < n_traces; trace++) {

                const uint8_t *pt = plaintexts + trace * 16; //aktueller pt

                uint8_t a0 = SBOX[pt[0] ^ k0];
                uint8_t a1 = SBOX[pt[5] ^ k5];
                uint8_t a2 = SBOX[pt[10] ^ k10];
                uint8_t a3 = SBOX[pt[15] ^ k15];

                uint8_t value = a0 ^ a1 ^ GMUL2[a2] ^ GMUL3[a3] ^ SBOX[k15]; // Zwischenwert der round2 Berechnung

                int predicted = (value ^ k2) >> 2; // vorhergesagte cache-zeile = (predicted_value XOR key_byte2_top6) >> 2

                double time = times[trace];
                // vergleich mit allen refbytes
                for (int i = 0; i < NREF; i++) {

                    int reference = (pt[REF_BYTES[i]] >> 2) ^ ref_top6[i]; //cache-zeile

                    // Kollision prüfen
                    if (predicted == reference) {
                        add_value(&collision[i], time);
                    } 
                    
                    else {
                        add_value(&no_collision[i], time);
                    }
                }
            }

            
            // t-werte kombinieren 
            double combined_score = 0.0;

            for (int i = 0; i < NREF; i++) {
                double t_value = t_test(
                    &collision[i],
                    &no_collision[i]
                );
                combined_score += t_value * t_value; // quadrate addieren, damit positive und negative t-Werte sich nicht gegenseitig aufheben
            }

            t_values[res_idx++] = sqrt(combined_score / NREF); // RMS-Score 
        }
    }
}




// brute force

// upper 6 bit aller keybytes bekannt, lower 2 von 12 kb unbekannt
// ->  4^12 = 2^24 kombinationen
int brute_force(const uint8_t top6_full[16], const uint8_t *test_pt, const uint8_t *test_ct, int n_tests, uint8_t found_key[16])
{
    init_tables();
    const int unknown_bytes[12] = {1,2,3,4,6,7,8,9,11,12,13,14}; 
    uint8_t key[16];
    memcpy(key, top6_full, 16);

    for (long combo = 0; combo < (1L << 24); combo++) {

        long rem_bits = combo; //remaining bits

        for (int i = 0; i < 12; i++) {
            key[unknown_bytes[i]] = (uint8_t)(top6_full[unknown_bytes[i]] | (rem_bits & 0x3));

            rem_bits >>= 2;
        }

        //Rundenschlüssel für aktuellen Kandidat
        uint8_t round_keys[176];

        key_expansion(key, round_keys);

        // test key
        int success = 1; // key is ok/correct;

        for (int trace = 0; trace < n_tests && success; trace++) {

            uint8_t ct[16];

            aes_encrypt(test_pt + trace*16, round_keys, ct);
            if (memcmp(ct, test_ct + trace*16, 16) != 0) {
                success = 0;
            }
        }
        if (success) { 
            memcpy(found_key, key, 16); 
            return 1; 
        }
    }
    return 0;
}

// verify key gegen alle 1.000.000 ciphertexts
int verify_key(const uint8_t key[16], const uint8_t *pts, const uint8_t *cts, int n_traces) 
{
    init_tables();
    uint8_t round_keys[176];

    key_expansion(key, round_keys); // rundenschlüssel

    int mismatches = 0;
    for (int trace = 0; trace < n_traces; trace++) 
    {
        uint8_t calc_ct[16]; //calculated ciphertext

        aes_encrypt(pts + trace*16, round_keys, calc_ct);
        if (memcmp(calc_ct, cts + trace*16, 16) != 0) {
            mismatches++;
        }
    }
    return mismatches;
}
