rule exemplo_maltest
{
    meta:
        description = "Exemplo benigno: dispara em arquivos com o marcador MALTEST-EXEMPLO"
        author = "exemplo"
    strings:
        $marcador = "MALTEST-EXEMPLO"
    condition:
        $marcador
}
