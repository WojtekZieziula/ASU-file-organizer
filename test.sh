#!/bin/bash

TEST_DIR="test_data"
MAIN_X="$TEST_DIR/X"
DIR_Y1="$TEST_DIR/Y1"
DIR_Y2="$TEST_DIR/Y2"
ALL_DIRS=("$MAIN_X" "$DIR_Y1" "$DIR_Y2")
TEMP_EXTS=(".tmp" ".bak" "~" ".swp")

CONTENT="Original content for Duplicates"


echo "--- Generating test files in directory: $TEST_DIR ---"

rm -rf "$TEST_DIR"
mkdir -p "$MAIN_X/sub_a" "$DIR_Y1" "$DIR_Y2"

echo "Creating empty and temporary files..."

for current_dir in "${ALL_DIRS[@]}"; do
    echo "> Processing directory: $current_dir"
    touch "$current_dir/empty_file.txt"

    for ext in "${TEMP_EXTS[@]}"; do
        dd if=/dev/urandom of="$current_dir/trash_file$ext" bs=1 count=50 2>/dev/null

        touch "$current_dir/empty_trash$ext"
    done
done

echo "--- Generating duplicates ---"

echo "$CONTENT" > "$MAIN_X/original_document.txt"
touch -t 202501010800 "$MAIN_X/original_document.txt"

echo "$CONTENT" > "$DIR_Y1/copy_of_document.txt"
touch -t 202505011200 "$DIR_Y1/copy_of_document.txt"

echo "$CONTENT" > "$MAIN_X/sub_a/newest_copy.txt"
touch -t 202511011000 "$MAIN_X/sub_a/newest_copy.txt"


echo "--- Generating files with invalid characters ---"

COUNTER=1
for current_dir in "${ALL_DIRS[@]}"; do

    touch "$current_dir/report:$COUNTER?#\$File.pdf"

    touch "$current_dir/name*'with\"quotes'.log"

    COUNTER=$((COUNTER + 1))
done
