LINK_BASE = 0x0000;

ENTRY( EntryPoint )

SECTIONS
{
    . = LINK_BASE;
    .text : {
        *( .text$A );
        *( .text$B );
        *( .text$C );
        *( .text$D );
        *( .text );
        *( .text.* );
        *( .rdata* );
        *( .data* );
        *( .idata* );
        *( .bss* );
        FILL( 0x00 )
        . = ALIGN( 0x1000 );
        __INSTANCE = .;
        . += 0x1000;
        *( .text$Z );
    }

    /DISCARD/ : {
        *( .pdata* );
        *( .xdata* );
        *( .eh_frame* );
    }
}
