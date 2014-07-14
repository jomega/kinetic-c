#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "kinetic.h"

int main(int argc, char** argv)
{
    size_t i, j;
    size_t len, len1, len2;
    KineticProto proto = KINETIC_PROTO_INIT;
    KineticProto* pproto;
    KineticProto_Command cmd = KINETIC_PROTO_COMMAND_INIT;
    KineticProto_Header header = KINETIC_PROTO_HEADER_INIT;
    uint8_t buffer[1024];
    ProtobufCBufferSimple bs = PROTOBUF_C_BUFFER_SIMPLE_INIT(buffer);
    uint8_t* packed;

    KineticProto_init(&proto);
    KineticProto_command_init(&cmd);
    KineticProto_header_init(&header);

    printf ("Seagate Kinetic Protocol C Client Test Utility\n\n");

    printf("KineticProto:\n");
    printf("  size: %lu\n", sizeof(proto));

    printf("  pre-packed size: %lu\n", KineticProto_get_packed_size(&proto));

    header.clusterversion = 12345678;
    header.has_clusterversion = true;
    printf("> clusterversion: %016llX\n", (unsigned long long)header.clusterversion);
    header.identity = -12345678;
    header.has_identity = true;
    printf("> identity: %016llX\n", (unsigned long long)header.identity);
    cmd.header = &header;
    proto.command = &cmd;

    len = KineticProto_get_packed_size(&proto);
    printf("  calculated packed size: %lu\n", len);


    printf("\nPacking message into raw allocated buffer...\n");
    packed = malloc(KineticProto_get_packed_size(&proto));
    assert(packed);
    len1 = KineticProto_pack(&proto, packed);
    printf("  actual packed size: %lu\n", len1);
    assert(len1 == len);
    assert(KineticProto_get_packed_size(&proto) == len1);
    printf("  buffer contents:\n");
    for (i = 0; i < len; i++)
    {
        printf("    ");
        for (j = 0; j < 8; j++, i++)
        {
            if (i < len)
            {
                printf("%02X ", packed[i]);
            }
        }
        printf("\n");
    }


    printf("\nPacking message into ProtobufCBufferSimple...\n");
    len2 = KineticProto_pack_to_buffer(&proto, &bs.base);
    printf("  actual packed size: %lu\n", len1);
    assert(len2 == len);
    assert(bs.len == len);
    assert(KineticProto_get_packed_size(&proto) == len);
    printf("  buffer contents:\n");
    for (i = 0; i < len; i++)
    {
        printf("    ");
        for (j = 0; j < 8; j++, i++)
        {
            if (i < len)
            {
                printf("%02X ", buffer[i]);
            }
        }
        printf("\n");
    }

    // Validate the both packed buffers are equal
    assert(memcmp (bs.data, packed, len) == 0);
    printf("  Simple and dynamically allocated buffers match!\n");
    PROTOBUF_C_BUFFER_SIMPLE_CLEAR (&bs);

    // Unpack and verify the simple buffer results
    printf("\nValidating unpacked ProtobufCBufferSimple contents...\n");
    pproto = KineticProto_unpack(NULL, len, bs.data);
    assert (pproto != NULL);
    assert (pproto->command->header->has_identity == true);
    assert (pproto->command->header->identity == -12345678ul);
    printf("< identity: %016llX\n", (unsigned long long)header.identity);
    assert (pproto->command->header->has_clusterversion == true);
    assert (pproto->command->header->clusterversion == 12345678ul);
    printf("< clusterversion: %016llX\n", (unsigned long long)header.clusterversion);

    // Unpack and verify the raw buffer results
    printf("\nValidating unpacked dynamically allocated buffer contents...\n");
    pproto = KineticProto_unpack(NULL, len, packed);
    assert (pproto != NULL);
    assert (pproto->command->header->has_identity == true);
    assert (pproto->command->header->identity == -12345678ul);
    printf("< identity: %016llX\n", (unsigned long long)header.identity);
    assert (pproto->command->header->has_clusterversion == true);
    assert (pproto->command->header->clusterversion == 12345678ul);
    printf("< clusterversion: %016llX\n", (unsigned long long)header.clusterversion);

    // Free dynamically allocated memory
    KineticProto_free_unpacked(pproto, NULL);
    free(packed);

    printf("\nKinetic C Client test utility ran successfully!\n");

    return 0;
}
