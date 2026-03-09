#ifndef SHADOWCALL_SHADOWCALL_HPP
#define SHADOWCALL_SHADOWCALL_HPP

#include <algorithm>
#include <compare>
#include <cstddef>
#include <cstdint>
#include <fstream>
#include <string>
#include <unordered_map>
#include <vector>
#include <windows.h>

namespace shadow {
    namespace detail {
        class address_t {
        public:
            address_t () = default;
            ~address_t () = default;

            address_t (std::nullptr_t) {}

            address_t (const std::uintptr_t address)
                : _address (address) {
            }

            address_t (const void* address)
                : _address (reinterpret_cast<std::uintptr_t> (address)) {
            }

            address_t (const address_t& other) {
                if (this != &other)
                    _address = other._address;
            }

            auto operator= (const address_t& other) -> address_t& {
                if (this != &other)
                    _address = other._address;

                return *this;
            }

            operator void*() const {
                return reinterpret_cast<void*> (_address);
            }

            operator std::uintptr_t () const {
                return _address;
            }

            operator bool () const {
                return _address != 0;
            }

            template <typename Ret = address_t>
            auto as () const -> Ret {
                return Ret (_address);
            }

            template <typename Ret = address_t>
            auto offset (const std::size_t offset) const -> Ret {
                return Ret (_address + offset);
            }

            template <typename Ret = address_t>
            auto get (std::size_t deref_count = 1) const -> Ret {
                std::uintptr_t return_address = _address;
                while (deref_count--)
                    if (return_address)
                        return_address = *reinterpret_cast<std::uintptr_t*> (return_address);

                return Ret (return_address);
            }

            template <typename Ret = address_t>
            auto jump (const std::ptrdiff_t offset_to_rel32 = 1) const -> Ret {
                std::uintptr_t return_address = _address + offset_to_rel32;
                return_address += *reinterpret_cast<std::int32_t*> (return_address);
                return_address += sizeof (std::int32_t);

                return Ret (return_address);
            }

            auto operator<=> (const address_t& other) const = default;

            auto operator+= (const address_t& other) -> address_t& {
                _address += other._address;
                return *this;
            }

            auto operator-= (const address_t& other) -> address_t& {
                _address -= other._address;
                return *this;
            }

        private:
            std::uintptr_t _address = 0;
        };

        namespace hash {
            using fnv1a64_t = std::uint64_t;

            constexpr std::uint64_t kFnvOffsetBasis = 0xcbf29ce484222325;
            constexpr std::uint64_t kFnvPrime = 0x100000001b3;

            constexpr auto fnv1a64 (const char* data, const std::size_t size) -> fnv1a64_t {
                fnv1a64_t hash = kFnvOffsetBasis;
                for (std::size_t idx = 0; idx < size; ++idx) {
                    hash ^= data [idx];
                    hash *= kFnvPrime;
                }

                return hash;
            }

            constexpr auto fnv1a64 (const char* str) -> fnv1a64_t {
                return fnv1a64 (str, strlen (str));
            }

            constexpr auto fnv1a64 (const std::string& str) -> fnv1a64_t {
                return fnv1a64 (str.data (), str.length ());
            }

            constexpr auto fnv1a64 (const std::string_view str) -> fnv1a64_t {
                return fnv1a64 (str.data (), str.length ());
            }
        } // namespace hash

        namespace win {
            constexpr std::int32_t kSectionAllAccess = 0x000F001F;
            constexpr std::int32_t kPageExecuteReadWrite = 0x40;
            constexpr std::int32_t kSecCommit = 0x08000000;
            constexpr std::int32_t kPageReadWrite = 0x4;
            constexpr std::int32_t kSecNoChange = 0x00400000;
            constexpr std::int32_t kPageExecuteRead = 0x20;

            enum class eSectionInherit {
                kViewShare = 1,
                kViewUnmap = 2
            };

            struct list_entry_t {
                list_entry_t* flink;
                list_entry_t* blink;
            };

            struct peb_ldr_data_t {
                std::uint32_t length;
                std::uint8_t initialized;
                void* ss_handle;
                list_entry_t in_load_order_module_list;
                list_entry_t in_memory_order_module_list;
                list_entry_t in_initialization_order_module_list;
                void* entry_in_progress;
            };

            struct peb_t {
                std::uint8_t inherited_address_space;
                std::uint8_t read_image_file_exec_options;
                std::uint8_t being_debugged;
                std::uint8_t bit_field;
                std::uint32_t image_uses_large_pages : 1;
                std::uint32_t is_protected_process : 1;
                std::uint32_t is_legacy_process : 1;
                std::uint32_t is_image_dynamically_relocated : 1;
                std::uint32_t spare_bites : 4;
                void* mutant;
                void* image_base_address;
                peb_ldr_data_t* ldr;
            };

            struct unicode_string_t {
                std::uint16_t length;
                std::uint16_t maximum_length;
                wchar_t* buffer;
            };

            struct ldr_data_table_entry_t {
                list_entry_t in_load_order_links;
                list_entry_t in_memory_order_links;
                list_entry_t in_initialization_order_links;
                void* dll_base;
                void* entry_point;
                std::uint32_t size_of_image;
                unicode_string_t full_dll_name;
                unicode_string_t base_dll_name;
            };

            struct image_dos_header_t {
                std::uint16_t e_magic;
                std::uint16_t e_cblp;
                std::uint16_t e_cp;
                std::uint16_t e_crlc;
                std::uint16_t e_cparhdr;
                std::uint16_t e_minalloc;
                std::uint16_t e_maxalloc;
                std::uint16_t e_ss;
                std::uint16_t e_sp;
                std::uint16_t e_csum;
                std::uint16_t e_ip;
                std::uint16_t e_cs;
                std::uint16_t e_lfarlc;
                std::uint16_t e_ovno;
                std::uint16_t e_res [4];
                std::uint16_t e_oemid;
                std::uint16_t e_oeminfo;
                std::uint16_t e_res2 [10];
                std::uint32_t e_lfanew;
            };

            struct image_file_header_t {
                std::uint16_t machine;
                std::uint16_t number_of_sections;
                std::uint32_t time_date_stamp;
                std::uint32_t pointer_to_symbol_table;
                std::uint32_t number_of_symbols;
                std::uint16_t size_of_optional_header;
                std::uint16_t characteristics;
            };

            struct image_data_directory_t {
                std::uint32_t virtual_address;
                std::uint32_t size;
            };

            struct image_optional_header64_t {
                std::uint16_t magic;
                std::uint8_t major_linker_version;
                std::uint8_t minor_linker_version;
                std::uint32_t size_of_code;
                std::uint32_t size_of_initialized_data;
                std::uint32_t size_of_uninitialized_data;
                std::uint32_t address_of_entry_point;
                std::uint32_t base_of_code;
                std::uint64_t image_base;
                std::uint32_t section_alignment;
                std::uint32_t file_alignment;
                std::uint16_t major_operating_system_version;
                std::uint16_t minor_operating_system_version;
                std::uint16_t major_image_version;
                std::uint16_t minor_image_version;
                std::uint16_t major_subsystem_version;
                std::uint16_t minor_subsystem_version;
                std::uint32_t win32_version_value;
                std::uint32_t size_of_image;
                std::uint32_t size_of_headers;
                std::uint32_t check_sum;
                std::uint16_t subsystem;
                std::uint16_t dll_characteristics;
                std::uint64_t size_of_stack_reserve;
                std::uint64_t size_of_stack_commit;
                std::uint64_t size_of_heap_reserver;
                std::uint64_t size_of_heap_commit;
                std::uint32_t lodaer_flags;
                std::uint32_t number_of_rva_and_sizes;
                union {
                    struct {
                        image_data_directory_t export_directory;       // 0
                        image_data_directory_t import_directory;       // 1
                        image_data_directory_t resource_directory;     // 2
                        image_data_directory_t exception_directory;    // 3
                        image_data_directory_t security_directory;     // 4
                        image_data_directory_t basereloc_directory;    // 5
                        image_data_directory_t debug_directory;        // 6
                        image_data_directory_t architecture_directory; // 7
                        image_data_directory_t globalptr_directory;    // 8
                        image_data_directory_t tls_directory;          // 9
                        image_data_directory_t load_config_directory;  // 10
                        image_data_directory_t bound_import_directory; // 11
                        image_data_directory_t iat_directory;          // 12
                        image_data_directory_t delay_import_directory; // 13
                        image_data_directory_t com_directory;          // 14
                        image_data_directory_t reserved;               // 15
                    };
                    image_data_directory_t data_directory [16];
                };
            };

            struct image_nt_headers {
                std::uint32_t signature;
                image_file_header_t file_header;
                image_optional_header64_t optional_header;
            };

            struct image_export_directory_t {
                std::uint32_t characteristics;
                std::uint32_t time_date_stamp;
                std::uint16_t major_version;
                std::uint16_t minor_version;
                std::uint32_t name;
                std::uint32_t base;
                std::uint32_t number_of_functions;
                std::uint32_t number_of_names;
                std::uint32_t address_of_functions;
                std::uint32_t address_of_names;
                std::uint32_t address_of_name_ordinals;
            };

            struct image_section_header_t {
                std::uint8_t name [8];
                union {
                    std::uint32_t physical_address;
                    std::uint32_t virtual_size;
                } misc;
                std::uint32_t virtual_address;
                std::uint32_t size_of_raw_data;
                std::uint32_t pointer_to_raw_data;
                std::uint32_t pointer_to_relocations;
                std::uint32_t pointer_to_linenumbers;
                std::uint16_t number_of_relocations;
                std::uint16_t number_of_linenumbers;
                std::uint32_t characteristics;
            };

            struct large_integer_t {
                union {
                    struct {
                        std::uint32_t low_part;
                        std::int32_t high_part;
                    };
                    std::int64_t quad_part;
                };
            };

            template <typename class_type, typename field_type>
            auto containing_record (field_type* field_addr, field_type class_type::* member_ptr) -> class_type* {
                if (!field_addr) {
                    return nullptr;
                }

                alignas (class_type) char dummy_buffer [sizeof (class_type)];
                const auto dummy_obj = reinterpret_cast<class_type*> (dummy_buffer);

                const std::ptrdiff_t offset = reinterpret_cast<char*> (&(dummy_obj->*member_ptr)) - reinterpret_cast<char*> (dummy_obj);
                return reinterpret_cast<class_type*> (reinterpret_cast<char*> (field_addr) - offset);
            }

            inline auto image_first_section (image_nt_headers* nt_headers) -> image_section_header_t* {
                if (!nt_headers) {
                    return nullptr;
                }

                const auto base_address = reinterpret_cast<std::uintptr_t> (nt_headers);
                constexpr std::ptrdiff_t optional_header_offset = offsetof (win::image_nt_headers, optional_header);

                const std::uintptr_t section_headers = base_address + optional_header_offset + nt_headers->file_header.size_of_optional_header;
                return reinterpret_cast<image_section_header_t*> (section_headers);
            }

            inline auto rva_to_raw (const std::uint32_t rva, image_nt_headers* nt_headers) -> std::uint32_t {
                const image_section_header_t* sections = image_first_section (nt_headers);
                for (std::uint32_t idx = 0; idx < nt_headers->file_header.number_of_sections; ++idx) {
                    const image_section_header_t* section = &sections [idx];
                    if (rva >= section->virtual_address && rva < section->virtual_address + section->misc.virtual_size)
                        return rva - section->virtual_address + section->pointer_to_raw_data;
                }

                return rva;
            }
        } // namespace win

        namespace str_transform {
            inline auto wstr_to_str (const std::wstring& data) -> std::string {
                if (data.empty ())
                    return {};

                const int required_length = WideCharToMultiByte (
                    CP_UTF8,
                    0,
                    &data [0],
                    static_cast<int> (data.size ()),
                    nullptr,
                    0,
                    nullptr,
                    nullptr);

                std::string result{};
                result.resize (required_length);
                WideCharToMultiByte (
                    CP_UTF8,
                    0,
                    &data [0],
                    static_cast<int> (data.size ()),
                    &result [0],
                    required_length,
                    nullptr,
                    nullptr);

                return result;
            }

            inline auto wstr_to_str (const std::wstring_view data) -> std::string {
                if (data.empty ())
                    return {};

                const int required_length = WideCharToMultiByte (
                    CP_UTF8,
                    0,
                    &data [0],
                    static_cast<int> (data.size ()),
                    nullptr,
                    0,
                    nullptr,
                    nullptr);

                std::string result{};
                result.resize (required_length);
                WideCharToMultiByte (
                    CP_UTF8,
                    0,
                    &data [0],
                    static_cast<int> (data.size ()),
                    &result [0],
                    required_length,
                    nullptr,
                    nullptr);

                return result;
            }

            inline auto to_lower (const std::string& data) -> std::string {
                std::string result{};
                result.resize (data.size ());

                for (std::size_t idx = 0; idx < data.size (); ++idx) {
                    char c = data [idx];
                    if (c >= 0x41 && c <= 0x5A)
                        c ^= 0x20;

                    result [idx] = c;
                }

                return result;
            }

            inline auto to_lower (const std::string_view data) -> std::string {
                std::string result{};
                result.resize (data.size ());

                for (std::size_t idx = 0; idx < data.size (); ++idx) {
                    char c = data [idx];
                    if (c >= 0x41 && c <= 0x5A)
                        c ^= 0x20;

                    result [idx] = c;
                }

                return result;
            }

            template <std::integral Ret>
            auto extract_number (const std::string& data) -> Ret {
                Ret result = 0;
                for (char c : data) {
                    if (c >= '0' && c <= '9')
                        result = result * 10 + (c - '0');
                    else
                        break;
                }

                return result;
            }

            template <std::integral Ret>
            auto extract_number (const std::string_view data) -> Ret {
                Ret result = 0;
                for (char c : data) {
                    if (c >= '0' && c <= '9')
                        result = result * 10 + (c - '0');
                    else
                        break;
                }

                return result;
            }
        } // namespace str_transform

        namespace view {
            class module_view_t {
            public:
                struct module_info_t {
                    address_t base;
                    hash::fnv1a64_t name;
                    hash::fnv1a64_t trimmed_nama;
                    std::string path;
                };

                module_view_t () {
                    _head = &get_peb ()->ldr->in_load_order_module_list;
                }

                auto skip_module () -> void {
                    _head = _head->flink;
                }

                class iterator {
                public:
                    using iterator_category = std::bidirectional_iterator_tag;
                    using value_type = module_info_t;
                    using difference_type = std::ptrdiff_t;
                    using pointer = value_type*;
                    using reference = value_type&;

                    iterator () = default;

                    iterator (win::list_entry_t* current, win::list_entry_t* head)
                        : _current (current), _head (head) {

                        update ();
                    }

                    pointer operator->() const {
                        return &_module_info;
                    }

                    reference operator* () const {
                        return _module_info;
                    }

                    iterator& operator++ () {
                        _current = _current->flink;
                        update ();
                        return *this;
                    }

                    iterator operator++ (int) {
                        iterator& temp = *this;
                        ++(*this);
                        return temp;
                    }

                    iterator& operator-- () {
                        _current = _current->blink;
                        update ();
                        return *this;
                    }

                    iterator operator-- (int) {
                        iterator& temp = *this;
                        --(*this);
                        return temp;
                    }

                    bool operator== (const iterator& other) const {
                        return _current == other._current;
                    }

                    bool operator!= (const iterator& other) const {
                        return _current != other._current;
                    }

                private:
                    mutable module_info_t _module_info;
                    win::list_entry_t* _current = nullptr;
                    win::list_entry_t* _head = nullptr;

                    auto update () -> void {
                        if (_current == _head)
                            return;

                        const win::ldr_data_table_entry_t* table_entry = win::containing_record (
                            _current,
                            &win::ldr_data_table_entry_t::in_load_order_links);

                        _module_info.base = table_entry->dll_base;

                        if (table_entry->full_dll_name.buffer && table_entry->full_dll_name.length > 0)
                            _module_info.path = str_transform::wstr_to_str (
                                std::wstring_view (table_entry->full_dll_name.buffer));

                        if (table_entry->base_dll_name.buffer && table_entry->base_dll_name.length > 0) {
                            std::string module_name = str_transform::wstr_to_str (
                                std::wstring_view (table_entry->base_dll_name.buffer));

                            module_name = str_transform::to_lower (module_name);

                            _module_info.name = hash::fnv1a64 (module_name);

                            _module_info.trimmed_nama = hash::fnv1a64 (
                                module_name.substr (0, module_name.length () - 4));
                        }
                    }
                };

                [[nodiscard]] iterator begin () const {
                    return {_head->flink, _head};
                }

                [[nodiscard]] iterator end () const {
                    return {_head, _head};
                }

                [[nodiscard]] iterator find (hash::fnv1a64_t module_name) const {
                    return std::ranges::find_if (begin (), end (), [module_name] (const module_info_t& m) -> bool {
                        return m.name == module_name;
                    });
                }

                template <typename Predicate>
                [[nodiscard]] iterator find_if (Predicate predicate) const {
                    return std::ranges::find_if (begin (), end (), predicate);
                }

            private:
                win::list_entry_t* _head;

                [[nodiscard]] static auto get_peb () -> win::peb_t* {
                    return reinterpret_cast<win::peb_t*> (__readgsqword (0x60));
                }
            };

            class export_view_t {
            public:
                struct export_info_t {
                    hash::fnv1a64_t name;
                    address_t address;
                    std::uint16_t ordinal;
                    bool is_forwarded;
                };

                export_view_t (const address_t& module_base)
                    : _module_base (module_base) {
                }

                [[nodiscard]] auto count () const -> uint32_t {
                    return export_directory ()->number_of_names;
                }

                [[nodiscard]] auto function (const std::uint16_t idx) const -> address_t {
                    const win::image_export_directory_t* export_dir = export_directory ();
                    const auto function_table = _module_base.offset<std::uint32_t*> (export_dir->address_of_functions);
                    const auto ordinal_table = _module_base.offset<std::uint16_t*> (export_dir->address_of_name_ordinals);

                    return _module_base.offset (function_table [ordinal_table [idx]]);
                }

                [[nodiscard]] auto name (const std::uint16_t idx) const -> hash::fnv1a64_t {
                    const win::image_export_directory_t* export_dir = export_directory ();
                    const auto name_table = _module_base.offset<std::uint32_t*> (export_dir->address_of_names);

                    auto export_name = _module_base.offset<const char*> (name_table [idx]);
                    return hash::fnv1a64 (std::string_view (export_name));
                }

                [[nodiscard]] auto ordinal (const std::uint16_t idx) const -> std::uint16_t {
                    const win::image_export_directory_t* export_dir = export_directory ();
                    const auto ordinal_table = _module_base.offset<std::uint16_t*> (export_dir->address_of_name_ordinals);

                    return export_dir->base + ordinal_table [idx];
                }

                [[nodiscard]] auto is_forwarded (const address_t& export_address) const -> bool {
                    const win::image_data_directory_t* export_data_dir = export_data_directory ();
                    const address_t export_start = _module_base.offset (export_data_dir->virtual_address);
                    const address_t export_end = export_start.offset (export_data_dir->size);

                    return export_address > export_start && export_address < export_end;
                }

                class iterator {
                public:
                    using iterator_category = std::bidirectional_iterator_tag;
                    using value_type = export_info_t;
                    using difference_type = std::ptrdiff_t;
                    using pointer = const value_type*;
                    using reference = const value_type&;

                    iterator () = default;

                    iterator (const export_view_t* export_view, const std::uint32_t current)
                        : _export_view (export_view), _current (current) {
                        update ();
                    }

                    pointer operator->() const {
                        return &_export_info;
                    }

                    reference operator* () const {
                        return _export_info;
                    }

                    iterator& operator++ () {
                        if (_current < _export_view->count ()) {
                            ++_current;
                            if (_current < _export_view->count ())
                                update ();
                            else
                                reset ();
                        } else {
                            reset ();
                        }
                        return *this;
                    }

                    iterator operator++ (int) {
                        iterator temp = *this;
                        ++(*this);
                        return temp;
                    }

                    iterator& operator-- () {
                        if (_current > 0) {
                            --_current;
                            update ();
                        }
                        return *this;
                    }

                    iterator operator-- (int) {
                        iterator temp = *this;
                        --(*this);
                        return temp;
                    }

                    bool operator== (const iterator& other) const {
                        return _current == other._current && _export_view == other._export_view;
                    }

                    bool operator!= (const iterator& other) const {
                        return _current != other._current || _export_view != other._export_view;
                    }

                private:
                    mutable export_info_t _export_info{};
                    const export_view_t* _export_view = nullptr;
                    std::uint32_t _current = 0;

                    auto update () -> void {
                        if (!_export_view || _current >= _export_view->count ())
                            return;

                        const address_t export_address = _export_view->function (_current);
                        _export_info = {
                            .name = _export_view->name (_current),
                            .address = export_address,
                            .ordinal = _export_view->ordinal (_current),
                            .is_forwarded = _export_view->is_forwarded (export_address)};
                    }

                    auto reset () -> void {
                        _export_info = export_info_t{};
                    }
                };

                [[nodiscard]] iterator begin () const {
                    return {this, 0};
                }

                [[nodiscard]] iterator end () const {
                    return {this, count ()};
                }

                [[nodiscard]] iterator find (hash::fnv1a64_t export_name) const {
                    return std::ranges::find_if (begin (), end (), [export_name] (const export_info_t& e) -> bool {
                        return e.name == export_name;
                    });
                }

                template <typename Predicate>
                [[nodiscard]] iterator find_if (Predicate predicate) const {
                    return std::ranges::find_if (begin (), end (), predicate);
                }

            private:
                address_t _module_base;

                [[nodiscard]] auto export_directory () const -> win::image_export_directory_t* {
                    const auto dos_header = _module_base.as<win::image_dos_header_t*> ();
                    const auto nt_headers = _module_base.offset<win::image_nt_headers*> (dos_header->e_lfanew);
                    const win::image_optional_header64_t* optional_header = &nt_headers->optional_header;

                    return _module_base.offset<win::image_export_directory_t*> (optional_header->export_directory.virtual_address);
                }

                [[nodiscard]] auto export_data_directory () const -> win::image_data_directory_t* {
                    const auto dos_header = _module_base.as<win::image_dos_header_t*> ();
                    const auto nt_headers = _module_base.offset<win::image_nt_headers*> (dos_header->e_lfanew);
                    const win::image_optional_header64_t* optional_header = &nt_headers->optional_header;

                    return const_cast<win::image_data_directory_t*> (&optional_header->export_directory);
                }
            };
        } // namespace view

        namespace apicalls {
            struct forwarded_string_t {
                hash::fnv1a64_t module_name;
                hash::fnv1a64_t proc_name;
                std::uint16_t ordinal;
                bool by_ordinal = false;
            };

            inline auto resolve_forwarded_string (const address_t& export_address) -> forwarded_string_t {
                const std::string_view forward_string = export_address.as<const char*> ();

                const std::size_t dot_delimiter = forward_string.find_first_of ('.');

                std::string trimmed_name (forward_string.substr (0, dot_delimiter));
                trimmed_name = str_transform::to_lower (trimmed_name);

                if (forward_string [dot_delimiter + 1] == '#') {
                    const std::string_view ordinal_str = forward_string.substr (dot_delimiter + 2);

                    const auto ordinal = str_transform::extract_number<std::uint16_t> (ordinal_str);

                    return {
                        .module_name = hash::fnv1a64 (trimmed_name),
                        .proc_name = 0,
                        .ordinal = ordinal,
                        .by_ordinal = true};
                }

                const std::string_view proc_name = forward_string.substr (dot_delimiter + 1);
                return {
                    .module_name = hash::fnv1a64 (trimmed_name),
                    .proc_name = hash::fnv1a64 (proc_name),
                    .ordinal = 0};
            }

            inline auto resolve_forwarded_export (const view::module_view_t& module_view, const address_t& forwarded_address) -> address_t {
                forwarded_string_t forwarded_string = resolve_forwarded_string (forwarded_address);
                const auto forward_module = module_view.find_if ([&forwarded_string] (const view::module_view_t::module_info_t& m) -> bool {
                    return m.trimmed_nama == forwarded_string.module_name;
                });

                if (forward_module == module_view.end ())
                    return {};

                const view::export_view_t e_view{forward_module->base};
                if (forwarded_string.by_ordinal) {
                    const auto _export = e_view.find_if ([&forwarded_string] (const view::export_view_t::export_info_t& e) -> bool {
                        return e.ordinal == forwarded_string.ordinal;
                    });

                    if (_export == e_view.end ())
                        return {};

                    return _export->address;
                }

                const auto _export = e_view.find (forwarded_string.proc_name);
                if (_export == e_view.end ())
                    return {};

                return _export->address;
            }

            inline auto find_export_by_name (const hash::fnv1a64_t module_name, const hash::fnv1a64_t export_name) -> address_t {
                view::module_view_t m_view;
                m_view.skip_module ();

                const auto module = m_view.find (module_name);
                if (module == m_view.end ())
                    return {};

                const view::export_view_t e_view{module->base};
                const auto _export = e_view.find (export_name);
                if (_export == e_view.end ())
                    return {};

                if (_export->is_forwarded)
                    return resolve_forwarded_export (m_view, _export->address);

                return _export->address;
            }

            inline auto find_export_by_name (const hash::fnv1a64_t export_name) -> address_t {
                view::module_view_t m_view;
                m_view.skip_module ();

                for (const auto& m : m_view) {
                    const view::export_view_t e_view{m.base};
                    const auto _export = e_view.find (export_name);
                    if (_export == e_view.end ())
                        continue;

                    if (_export->is_forwarded)
                        return resolve_forwarded_export (m_view, _export->address);

                    return _export->address;
                }

                return {};
            }

            inline auto find_export_by_ordinal (const hash::fnv1a64_t module_name, const std::uint16_t ordinal) -> address_t {
                view::module_view_t m_view;
                m_view.skip_module ();

                const auto module = m_view.find (module_name);
                if (module == m_view.end ())
                    return {};

                const view::export_view_t e_view{module->base};
                const auto _export = e_view.find_if ([&ordinal] (const view::export_view_t::export_info_t& e) -> bool {
                    return e.ordinal == ordinal;
                });

                if (_export == e_view.end ())
                    return {};

                if (_export->is_forwarded)
                    return resolve_forwarded_export (m_view, _export->address);

                return _export->address;
            }
        } // namespace apicalls

        template <typename T>
        auto normalize_arg (T arg) {
            if constexpr (std::is_same_v<T, std::nullptr_t>)
                return static_cast<void*> (nullptr);

            else if constexpr (std::is_integral_v<T>) {
                if constexpr (std::is_signed_v<T>)
                    return static_cast<std::intptr_t> (arg);
                else
                    return static_cast<std::uintptr_t> (arg);
            } else
                return arg;
        }
    } // namespace detail

    template <typename Ret = void, typename... Args>
    __declspec (noinline) auto call (const detail::hash::fnv1a64_t module_name, const detail::hash::fnv1a64_t proc_name, Args&&... args) -> Ret {
        using namespace detail;

        const address_t proc = apicalls::find_export_by_name (module_name, proc_name);
        if (!proc) {
            if constexpr (std::is_same_v<Ret, void>)
                return;
            else
                return Ret{};
        }

        using fn_t = Ret (*) (decltype (normalize_arg (std::forward<Args> (args)))...);
        const fn_t fn = proc.as<fn_t> ();

        return fn (normalize_arg (std::forward<Args> (args))...);
    }

    template <typename Ret = void, typename... Args>
    __declspec (noinline) auto call (const detail::hash::fnv1a64_t proc_name, Args&&... args) -> Ret {
        using namespace detail;

        const address_t proc = apicalls::find_export_by_name (proc_name);
        if (!proc) {
            if constexpr (std::is_same_v<Ret, void>)
                return;
            else
                return Ret{};
        }

        using fn_t = Ret (*) (decltype (normalize_arg (std::forward<Args> (args)))...);
        const fn_t fn = proc.as<fn_t> ();

        return fn (normalize_arg (std::forward<Args> (args))...);
    }

    template <typename Ret = void, typename... Args>
    __declspec (noinline) auto call (const detail::hash::fnv1a64_t module_name, const std::uint16_t ordinal, Args&&... args) -> Ret {
        using namespace detail;

        const address_t proc = apicalls::find_export_by_ordinal (module_name, ordinal);
        if (!proc) {
            if constexpr (std::is_same_v<Ret, void>)
                return;
            else
                return Ret{};
        }

        using fn_t = Ret (*) (decltype (normalize_arg (std::forward<Args> (args)))...);
        const fn_t fn = proc.as<fn_t> ();

        return fn (normalize_arg (std::forward<Args> (args))...);
    }

    namespace detail::syscalls {
        // clang-format off
        constexpr std::uint8_t kSyscallStub [] = {
            0x4C, 0x8B, 0xD1,             // mov r10, rcx
            0xB8, 0x00, 0x00, 0x00, 0x00, // mov eax, <syscall_number>
            0x0F, 0x05,                   // syscall
            0xC3,                         // retn
        };
        // clang-format on

        constexpr std::size_t kSyscallStubSize = sizeof (kSyscallStub);
        constexpr std::ptrdiff_t kSyscallStubOffsetToNumber = 0x4;
        constexpr std::uint32_t kSyscallSignature = 0xB8D18B4C;

        struct syscall_t {
            std::uint32_t number;
            std::uintptr_t start_offset;
        };

        inline bool _initialized = false;
        inline std::unordered_map<hash::fnv1a64_t, syscall_t> _syscall_map;
        inline address_t _syscall_region = nullptr;

        inline auto parse_syscalls () -> bool {
            view::module_view_t m_view;
            m_view.skip_module ();

            const auto ntdll = m_view.find (hash::fnv1a64 ("ntdll.dll"));
            if (ntdll == m_view.end ())
                return false;

            const std::string_view ntdll_path = ntdll->path;
            std::ifstream ntdll_file (ntdll_path.data (), std::ios::binary);
            if (!ntdll_file.is_open ())
                return false;

            const std::vector<std::uint8_t> ntdll_bytes ((std::istreambuf_iterator (ntdll_file)), std::istreambuf_iterator<char> ());
            ntdll_file.close ();

            const address_t ntdll_base = ntdll_bytes.data ();
            const auto dos_header = ntdll_base.as<win::image_dos_header_t*> ();
            const auto nt_headers = ntdll_base.offset<win::image_nt_headers*> (dos_header->e_lfanew);
            const auto optional_header = &nt_headers->optional_header;

            const auto export_directory = ntdll_base.offset<win::image_export_directory_t*> (rva_to_raw (
                optional_header->export_directory.virtual_address, nt_headers));

            const auto functions_rva = ntdll_base.offset<std::uint32_t*> (rva_to_raw (
                export_directory->address_of_functions, nt_headers));
            const auto names_rva = ntdll_base.offset<std::uint32_t*> (rva_to_raw (
                export_directory->address_of_names, nt_headers));
            const auto ordinals_rva = ntdll_base.offset<std::uint16_t*> (rva_to_raw (
                export_directory->address_of_name_ordinals, nt_headers));

            for (std::uint32_t idx = 0; idx < export_directory->number_of_names; ++idx) {
                const std::uint16_t ordinal = ordinals_rva [idx];
                address_t function_addr = ntdll_base.offset (rva_to_raw (
                    functions_rva [ordinal], nt_headers));

                if (*function_addr.as<std::uint32_t*> () != kSyscallSignature)
                    continue;

                const std::string_view syscall_name = ntdll_base.offset<const char*> (rva_to_raw (names_rva [idx], nt_headers));
                const std::uint32_t syscall_number = *function_addr.offset<std::uint32_t*> (kSyscallStubOffsetToNumber);

                syscall_t entry = {};
                entry.number = syscall_number;
                entry.start_offset = _syscall_map.size () * kSyscallStubSize;

                _syscall_map.emplace (hash::fnv1a64 (syscall_name), entry);
            }

            return true;
        }

        inline auto allocate_syscalls () -> bool {
            if (!parse_syscalls () || _syscall_map.empty ())
                return false;

            const std::size_t allocation_size = _syscall_map.size () * kSyscallStubSize;

            std::vector<std::uint8_t> syscall_buffer{};
            syscall_buffer.resize (allocation_size);
            for (const auto& [_, entry] : _syscall_map) {
                std::memcpy (syscall_buffer.data () + entry.start_offset, kSyscallStub, kSyscallStubSize);
                *reinterpret_cast<std::uint32_t*> (syscall_buffer.data () + entry.start_offset + kSyscallStubOffsetToNumber) = entry.number;
            }

            void* section_handle = nullptr;
            win::large_integer_t section_size{};
            section_size.quad_part = static_cast<std::int64_t> (allocation_size);
            auto status = call<std::int32_t> (hash::fnv1a64 ("ntdll.dll"), hash::fnv1a64 ("NtCreateSection"),
                                              &section_handle,
                                              win::kSectionAllAccess,
                                              nullptr,
                                              &section_size,
                                              win::kPageExecuteReadWrite,
                                              win::kSecCommit | win::kSecNoChange,
                                              nullptr);

            if (status < 0)
                return false;

            void* temp_view = nullptr;
            std::size_t view_size = allocation_size;
            status = call<std::int32_t> (hash::fnv1a64 ("ntdll.dll"), hash::fnv1a64 ("NtMapViewOfSection"),
                                         section_handle,
                                         -1,
                                         &temp_view,
                                         0,
                                         0,
                                         nullptr,
                                         &view_size,
                                         win::eSectionInherit::kViewShare,
                                         0,
                                         win::kPageReadWrite);

            if (status < 0)
                return false;

            std::memcpy (temp_view, syscall_buffer.data (), allocation_size);

            status = call<std::int32_t> (hash::fnv1a64 ("ntdll.dll"), hash::fnv1a64 ("NtUnmapViewOfSection"),
                                         -1,
                                         temp_view);

            if (status < 0) {
                call (hash::fnv1a64 ("ntdll.dll"), hash::fnv1a64 ("NtClose"), section_handle);
                return false;
            }

            void* region_address = nullptr;
            view_size = allocation_size;
            status = call<std::int32_t> (hash::fnv1a64 ("ntdll.dll"), hash::fnv1a64 ("NtMapViewOfSection"),
                                         section_handle,
                                         -1,
                                         &region_address,
                                         0,
                                         0,
                                         nullptr,
                                         &view_size,
                                         win::eSectionInherit::kViewShare,
                                         0,
                                         win::kPageExecuteRead);

            call (hash::fnv1a64 ("ntdll.dll"), hash::fnv1a64 ("NtClose"), section_handle);

            if (status < 0 || !region_address)
                return false;

            _syscall_region = region_address;
            return true;
        }
    } // namespace detail::syscalls

    template <typename... Args>
    __declspec (noinline) auto syscall (const detail::hash::fnv1a64_t syscall_name, Args&&... args) -> std::int32_t {
        using namespace detail;

        if (!syscalls::_initialized)
            syscalls::_initialized = syscalls::allocate_syscalls ();

        const auto syscall_entry = syscalls::_syscall_map.find (syscall_name);
        if (syscall_entry == syscalls::_syscall_map.end ())
            return {};

        const address_t proc = syscalls::_syscall_region.offset (syscall_entry->second.start_offset);

        using fn_t = std::int32_t (*) (decltype (normalize_arg (std::forward<Args> (args)))...);
        const fn_t fn = proc.as<fn_t> ();

        return fn (normalize_arg (std::forward<Args> (args))...);
    }
} // namespace shadow

consteval auto operator""_fnv1a64 (const char* literal, const std::size_t length) -> shadow::detail::hash::fnv1a64_t {
    return shadow::detail::hash::fnv1a64 (literal, length);
}

#endif // SHADOWCALL_SHADOWCALL_HPP