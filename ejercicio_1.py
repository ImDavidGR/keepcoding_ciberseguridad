def xor_data(binary_data_a, binary_data_b):
    result = []
    for bd1, bd2 in zip(binary_data_a, binary_data_b):
        xor_result = bd1 ^ bd2
        result.append(xor_result)
    return bytes(result)


# Solved with CyberChef
# https://gchq.github.io/CyberChef/#recipe=From_Hex('None')XOR(%7B'option':'Hex','string':'91BA13BA21AABB12'%7D,'Standard',false)To_Hex('None',0)&input=QjFFRjJBQ0ZFMkJBRUVGRg

clave_fija_1 = bytes.fromhex("B1EF2ACFE2BAEEFF")
clave_final_1 = bytes.fromhex("91BA13BA21AABB12")
clave_key_manager_1 = xor_data(clave_fija_1, clave_final_1)
print("Clave Key Manager:", clave_key_manager_1.hex().upper())
# RESPUESTA: Clave Key Manager: 20553975C31055ED

# --------------------------------------------

# Solved with CyberChef
# https://gchq.github.io/CyberChef/#recipe=From_Hex('None')XOR(%7B'option':'Hex','string':'B98A15BA31AEBB3F'%7D,'Standard',false)To_Hex('None',0)&input=QjFFRjJBQ0ZFMkJBRUVGRg

clave_fija_2 = int("B1EF2ACFE2BAEEFF", 16)
clave_key_manager_2 = int("B98A15BA31AEBB3F", 16)
clave_final_2 = clave_fija_2 ^ clave_key_manager_2
print(f"Clave Final: {clave_final_2:016X}")
# RESPUESTA: Clave Final: 08653F75D31455C0
