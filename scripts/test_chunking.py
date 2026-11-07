from backend.log_reader import read_log

from backend.model_client import LocalTokenizer

from backend.chunker import (
    create_chunks,
    MAX_CONTEXT,
    RESERVED_OUTPUT,
    SAFETY_MARGIN
)


LOG_PATH = "data/Cultive8_Workspace_Agrigen_Server.log"


def test_log_reader():

    entries = list(read_log(LOG_PATH))

    print("Total log entries:", len(entries))
    print("First line:", entries[0].line_number)
    print("Last line:", entries[-1].line_number)

    return entries


def test_chunking(entries):

    tokenizer = LocalTokenizer()

    chunks = list(
        create_chunks(entries, tokenizer)
    )

    print("\nTotal chunks:", len(chunks))

    for chunk in chunks:

        first_line = chunk.entries[0].line_number
        last_line = chunk.entries[-1].line_number

        total_tokens = (
            chunk.prompt_tokens
            + RESERVED_OUTPUT
            + SAFETY_MARGIN
        )

        print(
            f"Chunk {chunk.index}: "
            f"Lines {first_line}-{last_line}, "
            f"Entries={len(chunk.entries)}, "
            f"Prompt tokens={chunk.prompt_tokens}, "
            f"Total budget={total_tokens}"
        )

        assert total_tokens <= MAX_CONTEXT

    original_lines = [
        entry.line_number
        for entry in entries
    ]

    chunk_lines = [
        entry.line_number
        for chunk in chunks
        for entry in chunk.entries
    ]

    assert original_lines == chunk_lines

    print("\nAll original entries preserved: YES")
    print("All chunks fit token budget: YES")


if __name__ == "__main__":

    entries = test_log_reader()

    test_chunking(entries)