#!/usr/bin/env sage

F2 = GF(2)
R2.<X> = F2[]

F8_mod = X^8 + X^4 + X^3 + X + 1

F8 = GF(2^8, name='z8', modulus=F8_mod)
RF8 = F8['x']

F64 = GF(2^64, name='z64', modulus=X^64 + X^4 + X^3 + X + 1)
F128 = GF(2^128, name='z128', modulus=X^128 + X^7 + X^2 + X + 1)
F192 = GF(2^192, name='z192', modulus=X^192 + X^7 + X^2 + X + 1)
F256 = GF(2^256, name='z256', modulus=X^256 + X^10 + X^5 + X^2 + 1)

def poly_to_int(a):
    return int(R2(a).change_ring(ZZ)(2))

def fe_to_bytes(byte_size, a):
    return poly_to_int(a).to_bytes(byte_size, 'little')

def fe_list_to_cpp_array(byte_size, xs):
    return '{\n\t{' + '},\n\t{'.join(', '.join([f'0x{a:02x}' for a in fe_to_bytes(byte_size, x)]) for x in xs) + '}\n}'

def get_root(field):
    roots = [r for r, m in F8_mod.change_ring(field).roots()]
    for r0, r1 in zip(roots[:-1], roots[1:]):
        # Sage outputs in lexiographic order:
        assert(r0.to_integer() < r1.to_integer())

    # Arbitrarily pick the lexiographically first root.
    return roots[0]

def get_extension_modulus(field, root):
    for mod, _ in RF8(field.modulus()).factor():
        assert(mod.degree() == field.degree() // 8)
        assert(mod.monomial_coefficient(RF8.gen()^(field.degree() // 8)) == 1)
        if sum(m.change_ring(F2)(field.gen()) * mod.monomial_coefficient(m).polynomial()(root) for m in mod.monomials()) == 0:
            return mod

def print_root_powers(field, root):
    assert(field.degree() % 8 == 0)
    print(fe_list_to_cpp_array(field.degree(), [root^i for i in range(1, F8_mod.degree())]))

for field in [F64, F128, F192, F256]:
    print(f"F{field.degree()}")

    root = get_root(field)
    print_root_powers(field, root)

    field_over_F8 = F8.extension(get_extension_modulus(field, root))
    encoded_powers = []
    for i in range(field.degree()):
        power = (field_over_F8.gen()^i).lift()
        # Do something like Kronecker substitution to encode the element of field_over_F8.
        encoded_powers.append(sum(m.change_ring(F2)(R2.gen()^8) * power.monomial_coefficient(m).polynomial()(R2.gen()) for m in power.monomials()))
    print(fe_list_to_cpp_array(field.degree() // 8, encoded_powers))

    print("")
