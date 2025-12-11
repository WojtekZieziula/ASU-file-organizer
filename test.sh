#!/bin/bash

# --- KONFIGURACJA ---
TEST_DIR="test_data"
MAIN_X="$TEST_DIR/X"
DIR_Y1="$TEST_DIR/Y1"
DIR_Y2="$TEST_DIR/Y2"
ALL_DIRS=("$MAIN_X" "$DIR_Y1" "$DIR_Y2")
TEMP_EXTS=(".tmp" ".bak" "~" ".swp")
CONTENT_A="Content for Duplicates Group A"
CONTENT_B="Unique content for Conflict B"
CONTENT_C="Content for Conflict C (Older)"

echo "--- Generating Test Environment in $TEST_DIR ---"

rm -rf "$TEST_DIR"
mkdir -p "$MAIN_X/sub_a" "$DIR_Y1/sub_b" "$DIR_Y2/sub_c"


echo "--- Generating temporary and empty files ---"

for current_dir in "${ALL_DIRS[@]}"; do
    echo "> Processing directory: $current_dir"
    touch "$current_dir/empty_file.txt"
    touch "$current_dir/sub_a/empty_file_sub.txt"
    for ext in "${TEMP_EXTS[@]}"; do
        dd if=/dev/urandom of="$current_dir/trash_file$ext" bs=1 count=50 2>/dev/null
    done
done


echo "--- Generating duplicates ---"

echo "$CONTENT_A" > "$MAIN_X/original_document.txt"
touch -t 202501010800 "$MAIN_X/original_document.txt"

echo "$CONTENT_A" > "$DIR_Y1/copy_of_document.txt"
touch -t 202405011200 "$DIR_Y1/copy_of_document.txt"

echo "$CONTENT_A" > "$MAIN_X/sub_a/newest_copy.txt"
touch -t 202511011000 "$MAIN_X/sub_a/newest_copy.txt"


echo "--- Generating files with bad chars ---"

COUNTER=1
for current_dir in "${ALL_DIRS[@]}"; do
    touch "$current_dir/report:$COUNTER?#\$File.pdf"
    touch "$current_dir/name*'with\"quotes and space'.log"
    touch "$current_dir/ends_with_colon:.txt"
    touch "$current_dir/#starts_with_hash.doc"

    COUNTER=$((COUNTER + 1))
done


echo "--- Generating permissions issues ---"

touch "$MAIN_X/unusual_perms_A.sh"
chmod 777 "$MAIN_X/unusual_perms_A.sh"

touch "$DIR_Y1/unusual_perms_B.sh"
chmod 420 "$DIR_Y1/unusual_perms_B.sh"

echo "--- Generating consolidation conflicts ---"

# SCENARIUSZ A: Duplikat (ten sam Hash) z konfliktem nazw (test na priorytet)
# W zasadzie pokryte przez sekcję 2, ale dodajemy plik o tej samej nazwie.
echo "$CONTENT_A" > "$MAIN_X/same_name_dupe.txt" # Hash A, 2025-01-01
touch -t 202501010800 "$MAIN_X/same_name_dupe.txt"
echo "$CONTENT_A" > "$DIR_Y1/same_name_dupe.txt" # Hash A, 2025-11-01
touch -t 202511011000 "$DIR_Y1/same_name_dupe.txt"
# Oczekiwane: --dupes usuwa ten z Y1. --move nie powinien nic robić, bo jest ten sam hash.

# SCENARIUSZ B: Konflikt RÓŻNEJ ZAWATOŚCI (Ten sam Name, Różny Hash)
# Wymóg: Zachowaj NOWSZY plik.
echo "$CONTENT_C" > "$MAIN_X/conflict_file.txt" # Stary plik w X (Zawartość C)
touch -t 202401010800 "$MAIN_X/conflict_file.txt"

echo "$CONTENT_B" > "$DIR_Y2/conflict_file.txt" # Nowszy plik w Y2 (Zawartość B)
touch -t 202501010800 "$DIR_Y2/conflict_file.txt"
# Oczekiwane: Po --move, plik z Y2 powinien zastąpić plik z X (bo jest nowszy).

# SCENARIUSZ C: Plik do przeniesienia, który nie powoduje konfliktu
echo "Unique content" > "$DIR_Y1/file_to_move_alone.log"
# Oczekiwane: Po --move, plik z Y1 zostaje przeniesiony do X.

