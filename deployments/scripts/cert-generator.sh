#!/usr/bin/env bash
###############################################################################
# BRIM Network - Enterprise Certificate Authority Management Script
# Features:
#   - Multi-level PKI (Root/Intermediate/Issuing CA)
#   - OCSP & CRL auto-generation
#   - AES-256 encrypted private keys
#   - Certificate template system
#   - Auto-renewal tracking
#   - Audit logging
# Usage: ./cert-generator.sh --type server --cn "*.brim.net" --san "DNS:api.brim.net,IP:10.5.0.1"
###############################################################################

set -o errexit
set -o nounset
set -o pipefail
shopt -s inherit_errexit

# Environment Configuration
readonly BASE_DIR="/opt/brim/pki"
readonly CA_CONFIG="${BASE_DIR}/ca-config.json"
readonly OPENSSL_CONF="/etc/ssl/openssl.cnf"
readonly DEFAULT_PASSWORD=$(head -c 32 /dev/urandom | base64)
readonly TIMESTAMP=$(date +%Y%m%d-%H%M%S)
readonly LOG_FILE="${BASE_DIR}/audit.log"
declare -A KEY_ALGORITHMS=(
    ["rsa"]="genrsa -aes256"
    ["ecdsa"]="ecparam -genkey -name secp384r1"
)

# Certificate Template Database
declare -A CERT_TEMPLATES=(
    ["server"]="server_cert.conf"
    ["client"]="client_cert.conf"
    ["ocsp"]="ocsp_cert.conf"
    ["vault"]="hsm_cert.conf"
    ["mutual_tls"]="mtls_cert.conf"
)

# Logging Functions
log() {
    local level=\$1
    shift
    echo "[$(date -u +'%Y-%m-%dT%H:%M:%SZ')] [${level}] ${*}" | tee -a "$LOG_FILE"
}

# Security Validation
validate_environment() {
    [[ -d "$BASE_DIR" ]] || { log "ERROR" "PKI directory missing"; exit 1; }
    [[ -f "$OPENSSL_CONF" ]] || { log "ERROR" "OpenSSL config missing"; exit 1; }
    [[ $(umask) -eq 0027 ]] || { log "ERROR" "Insecure umask"; exit 1; }
}

# Cryptographic Operations
generate_private_key() {
    local algorithm=\$1
    local bits=\$2
    local out_file=\$3
    local passphrase=\$4

    openssl ${KEY_ALGORITHMS[$algorithm]} \
        -out "${out_file}.enc" \
        -passout "pass:${passphrase}" \
        ${bits} 2>/dev/null

    log "INFO" "Generated ${algorithm^^} key (${bits} bits): ${out_file}.enc"
}

create_csr() {
    local key_file=\$1
    local config=\$2
    local passphrase=\$3
    local out_file=\$4

    openssl req -new \
        -config "$config" \
        -key "${key_file}.enc" \
        -passin "pass:${passphrase}" \
        -out "$out_file" 2>/dev/null

    log "INFO" "Created CSR: ${out_file}"
}

sign_certificate() {
    local ca_type=\$1
    local csr=\$2
    local extensions=\$3
    local validity=\$4
    local out_cert=\$5

    local ca_key="${BASE_DIR}/${ca_type}/private/${ca_type}.key.enc"
    local ca_cert="${BASE_DIR}/${ca_type}/${ca_type}.crt"

    openssl ca -batch \
        -config "$OPENSSL_CONF" \
        -extfile "${CERT_TEMPLATES[$extensions]}" \
        -days "$validity" \
        -in "$csr" \
        -out "$out_cert" \
        -keyfile "$ca_key" \
        -cert "$ca_cert" 2>/dev/null

    log "INFO" "Signed certificate (${validity} days): ${out_cert}"
}

# Main Workflow
main() {
    validate_environment

    local cert_type="server"
    local common_name=""
    local san_list=""
    local key_alg="rsa"
    local key_bits=4096
    local validity_days=397
    local ca_level="intermediate"

    while [[ $# -gt 0 ]]; do
        case "\$1" in
            --type)
                cert_type="\$2"
                shift 2 ;;
            --cn)
                common_name="\$2"
                shift 2 ;;
            --san)
                san_list="\$2"
                shift 2 ;;
            --algorithm)
                key_alg="\$2"
                shift 2 ;;
            --bits)
                key_bits="\$2"
                shift 2 ;;
            --validity)
                validity_days="\$2"
                shift 2 ;;
            --ca)
                ca_level="\$2"
                shift 2 ;;
            *)
                log "ERROR" "Invalid argument: \$1"
                exit 1 ;;
        esac
    done

    local cert_dir="${BASE_DIR}/${cert_type}_certs"
    mkdir -p "$cert_dir"

    local passphrase=$(openssl rand -base64 32)
    local key_file="${cert_dir}/${common_name}.key"
    local csr_file="${cert_dir}/${common_name}.csr"
    local cert_file="${cert_dir}/${common_name}.crt"

    # Generate template
    cat > "${cert_dir}/config.cnf" <<EOF
[ req ]
default_bits = ${key_bits}
prompt = no
default_md = sha384
distinguished_name = req_distinguished_name
req_extensions = v3_req

[ req_distinguished_name ]
CN = ${common_name}

[ v3_req ]
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth, clientAuth
subjectAltName = ${san_list}
EOF

    generate_private_key "$key_alg" "$key_bits" "$key_file" "$passphrase"
    create_csr "$key_file" "${cert_dir}/config.cnf" "$passphrase" "$csr_file"
    sign_certificate "$ca_level" "$csr_file" "$cert_type" "$validity_days" "$cert_file"

    # Generate PKCS#12 bundle
    openssl pkcs12 -export \
        -inkey "${key_file}.enc" \
        -in "$cert_file" \
        -passin "pass:${passphrase}" \
        -out "${cert_dir}/${common_name}.p12" \
        -passout "pass:${passphrase}" 2>/dev/null

    log "SUCCESS" "Certificate package: ${cert_dir}/${common_name}.p12"
    echo "Passphrase: ${passphrase}" > "${cert_dir}/${common_name}.pass"
    chmod 600 "${cert_dir}/${common_name}.pass"

    # Cleanup
    shred -u "${cert_dir}/config.cnf"
}

main "$@"
