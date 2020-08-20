#include "signature.h"

void init_signature_list(signature **signature_list)
{
	/*document*/
	add_signature_node(signature_list, ".ppt", "00 6E 1E F0", 4, 512);
	add_signature_node(signature_list, ".ppt", "A0 46 1D F0", 4, 512);
	add_signature_node(signature_list, ".ppt", "FD FF FF FF 0E 00 00 00", 8, 512);
	add_signature_node(signature_list, ".ppt", "FD FF FF FF 1C 00 00 00", 8, 512);
	add_signature_node(signature_list, ".ppt", "FD FF FF FF 43 00 00 00", 8, 512);
	add_signature_node(signature_list, ".ppt", "0F 00 E8 03", 4, 512);
	add_signature_node(signature_list, ".ppt", "D0 CF 11 E0 A1 B1 1A E1", 8, 0);
	add_signature_node(signature_list, ".pptx", "50 4B 03 04", 4, 0);
	add_signature_node(signature_list, ".pptx", "50 4B 03 04 14 00 06 00", 8, 0);
	add_signature_node(signature_list, ".xls", "D0 CF 11 E0 A1 B1 1A E1", 8, 0);
	add_signature_node(signature_list, ".xls", "09 08 10 00 00 06 05 00", 8, 512);
	add_signature_node(signature_list, ".xls", "FD FF FF FF 10 00", 6, 512);
	add_signature_node(signature_list, ".xls", "FD FF FF FF 1F 00", 6, 512);
	add_signature_node(signature_list, ".xls", "FD FF FF FF 22 00", 6, 512);
	add_signature_node(signature_list, ".xls", "FD FF FF FF 23 00", 6, 512);
	add_signature_node(signature_list, ".xls", "FD FF FF FF 28 00", 6, 512);
	add_signature_node(signature_list, ".xls", "FD FF FF FF 29 00", 6, 512);
	add_signature_node(signature_list, ".xls", "FD FF FF FF 10 02", 6, 512);
	add_signature_node(signature_list, ".xls", "FD FF FF FF 1F 02", 6, 512);
	add_signature_node(signature_list, ".xls", "FD FF FF FF 22 02", 6, 512);
	add_signature_node(signature_list, ".xls", "FD FF FF FF 23 02", 6, 512);
	add_signature_node(signature_list, ".xls", "FD FF FF FF 28 02", 6, 512);
	add_signature_node(signature_list, ".xls", "FD FF FF FF 29 02", 6, 512);
	add_signature_node(signature_list, ".xls", "FD FF FF FF 20 00 00 00", 8, 512);
	add_signature_node(signature_list, ".xlsx", "50 4B 03 04", 4, 0);
	add_signature_node(signature_list, ".xlsx", "50 4B 03 04 14 00 06 00", 8, 0);
	add_signature_node(signature_list, ".doc", "D0 CF 11 E0 A1 B1 1A E1", 8, 0);
	add_signature_node(signature_list, ".doc", "EC A5 C1 00", 4, 512);
	add_signature_node(signature_list, ".doc", "0D 44 4F 43", 4, 0);
	add_signature_node(signature_list, ".doc", "31 BE 00 00 00 AB", 6, 0);
	add_signature_node(signature_list, ".doc", "7F FE 34 0A", 4, 0);
	add_signature_node(signature_list, ".doc", "9B A5", 2, 0);
	add_signature_node(signature_list, ".doc", "DB A5 2D 00", 4, 0);
	add_signature_node(signature_list, ".doc", "12 34 56 78 90 FF", 6, 0);
	add_signature_node(signature_list, ".doc", "CF 11 E0 A1 B1 1A E1 00", 8, 0);
	add_signature_node(signature_list, ".docx", "50 4B 03 04", 4, 0);
	add_signature_node(signature_list, ".docx", "50 4B 03 04 14 00 06 00", 8, 0);
	add_signature_node(signature_list, ".pdf", "25 50 44 46", 4, 0);

	/*image*/
	add_signature_node(signature_list, ".jpg", "FF D8 FF E0 00 10 4A 46 49 46 00 01", 12, 0);
	add_signature_node(signature_list, ".jpg", "FF D8 FF E1 xx xx 45 78 69 66 00 00", 12, 0);
	add_signature_node(signature_list, ".jpg", "FF D8 FF E8 xx xx 53 50 49 46 46 00", 12, 0);
	add_signature_node(signature_list, ".png", "89 50 4E 47 0D 0A 1A 0A", 8, 0);

	/*music*/
	add_signature_node(signature_list, ".mp3", "49 44 33", 3, 0);
	add_signature_node(signature_list, ".mp3", "FF FB", 2, 0);
	add_signature_node(signature_list, ".flac", "66 4C 61 43", 4, 0);

	/*media*/
	add_signature_node(signature_list, ".mp4", "66 74 79 70 4D 53 4E 56", 8, 4);
	add_signature_node(signature_list, ".mp4", "66 74 79 70 4D 53 4E 56", 8, 4);
	add_signature_node(signature_list, ".mp4", "66 74 79 70 69 73 6F 6D", 8, 4);
	add_signature_node(signature_list, ".mp4", "00 00 00 18 66 74 79 70 33 67 70 35", 12, 0);
	add_signature_node(signature_list, ".mkv", "1A 45 DF A3", 4, 0);

	printk("Signature Init Complete\n");
}

signature *make_signature_node(char ext[5], char *sig_shape_str, int sig_shape_str_size, int offset)
{
	signature *new_sig = kmalloc(sizeof(signature), GFP_KERNEL);
	strcpy(new_sig->ext, ext);
	new_sig->data = parsing_signature(sig_shape_str, sig_shape_str_size);
	new_sig->size = sig_shape_str_size;
	new_sig->offset = offset;
	new_sig->prev = NULL;
	new_sig->next = NULL;
	
	return new_sig;
}

void add_signature_node(signature **head, char ext[5], char *sig_shape_str, int sig_shape_str_size, int offset)
{
	signature *ptr = *head;
	
	if(ptr == NULL)
	{
		*head = make_signature_node(ext, sig_shape_str, sig_shape_str_size, offset);
		return;
	}
	
	while(ptr->next != NULL)
		ptr = ptr->next;
		
	ptr->next = make_signature_node(ext, sig_shape_str, sig_shape_str_size, offset);
	ptr->next->prev = ptr;
}

void printk_signature_nodes(signature *head)
{
	/* I used this function to test or debug */

	char print_buf[128];

	printk("--------------added signatures list--------------\n");
	if(head == NULL)
		printk("NULL\n");

	signature *ptr = head;
	
	while(ptr != NULL)
	{
		int i, p = 0;
		
		memset(print_buf, 0, sizeof(print_buf));
		p += snprintf(print_buf, 9, "%5s | ", ptr->ext);
			
		for(i = 0; i < ptr->size; i++)
		{
			p += snprintf(print_buf + p, 5, "%x%x ", (ptr->data)[i] >> 4, (ptr->data)[i] & 15);		
		}
		printk("%s| %d | %u\n", print_buf, ptr->size, ptr->offset);
		ptr = ptr->next;
	}
	printk("-----------------------------------------------\n");
}

void flush_signature_nodes(signature **head)
{
	/* make linked list NULL */

	signature *ptr;

	while(*head != NULL)
	{
		ptr = *head;
		*head = (*head)->next;
		kfree(ptr);
	}
}

unsigned char parsing_hex(char ch)
{
	/* if the character ch's value is 'f',
	   this function returns the hex value 15. */

	if('0' <= ch && ch <= '9')
	{
		return ch - 48; // because ASCII number of '0' is 48
	}
	else if('A' <= ch && ch <= 'F')
	{
		return ch - 55; // because ASCII number of 'A' is 65
	}
	else if('a' <= ch && ch <= 'f')
	{
		return ch - 87; // because ASCII number of 'a' is 97
	}
	else
		return 255;
}

unsigned char *parsing_signature(char *sig_shape_str, int sig_shape_str_size)
{
	/*
	if sig_shape_str is "AB CD EF 01 23 45 67 89",
	ret_sig will be the data {10*(2**4)+11, 12*(2**4)+13, 14*(2**4)+15, 0*(2**4)+1, 2*(2**4)+3, 4*(2**4)+5, 6*(2**4)+7, 8*(2**4)+9};
				       ab            cd            ef           01          23          45          67          89
	*/

	char *sig_shape_ptr = sig_shape_str;
	unsigned char *ret_sig = kmalloc(sizeof(unsigned char) * sig_shape_str_size, GFP_KERNEL);
	unsigned char *ret_sig_ptr = ret_sig;
	unsigned char temp;	
	int count = 0;

	while(*sig_shape_ptr != '\0')
	{
		if(*sig_shape_ptr == ' ')
		{
			sig_shape_ptr++;
			continue;
		}
		
		temp = 0;
		/*
		if the partial value of sig_shape_str is "A7",
		*sig_shape_ptr is 'A', and the next character is '7'.
		Additionally, binary value of 'A' and '7' are 1010 and 0111.
		So, 1010 -> 10100000 and 0111 is merged to 10100111.
		Finally, temp is will be hex value A7.
		*/
		temp += parsing_hex(*sig_shape_ptr) << 4;
		temp += parsing_hex(*(sig_shape_ptr + 1));

		*ret_sig_ptr = temp;

		sig_shape_ptr += 2;
		ret_sig_ptr++;
	}

	return ret_sig;
}

int check_signature(char *file_path, signature *signature_list, int size)
{
	/* To get file's signature status data
		1) #define IS_HAVING_TARGET_EXT 1	// To check if file has the target extension
		2) #define IS_EMPTY_FILE 2	// To check if file size is 0
		3) #define IS_TEMP_FILE 4	// To check if file name has the shape like ".~lock.[name].ext#" or ".[name].swx" or ".[name].swp"
		4) #define IS_INFECTED_EXT 8	// To check if file extension's shape is like ".doc.abc" or ".pptx.crypto" or etc.
		5) #define IS_INFECTED_SIG 16	// To check if file has the signature when the file is displayed in hexadecimal data */

	int ret = 0;

	if(size == 0)
		ret += IS_EMPTY_FILE;

	int i;
	struct file *fp;
	signature *ptr = signature_list;
	unsigned char sign[MAX_SIG_SHAPE_SIZE], temp[MAX_SIG_SHAPE_SIZE];
	char real_file_name[NAME_MAX];
	memset(temp, 0, MAX_SIG_SHAPE_SIZE);
	memset(real_file_name, 0, NAME_MAX);

	for(i = strlen(file_path) - 1; file_path[i] != '/'; i--);
	make_real_file_name(file_path + i + 1, real_file_name);

	if(strcmp(file_path + i + 1, real_file_name))
		ret += IS_TEMP_FILE;

	for(i = 0; i < strlen(real_file_name); i++)
		if(real_file_name[i] == '.')
			break;

	while(ptr != NULL)
	{
		if(strstr(real_file_name + i, ptr->ext))
		{
			ret += IS_HAVING_TARGET_EXT;

			if(strcmp(real_file_name + i, ptr->ext))
				ret += IS_INFECTED_EXT;

			if((ret & IS_EMPTY_FILE) || (ret & IS_TEMP_FILE))
				break;

			mm_segment_t oldfs = get_fs();
			set_fs(get_ds());

			fp = filp_open(file_path, O_RDONLY, 0);
			if(!IS_ERR(fp))
			{
				/* 1) When the file is displayed in hexadecimal data,
				      check whether the signature exists at a position offset
				      from the starting point or not */

				vfs_llseek(fp, 0, SEEK_SET);
				vfs_read(fp, temp, ptr->size, &fp->f_pos);

				vfs_llseek(fp, ptr->offset, SEEK_SET);
				vfs_read(fp, temp, MAX_SIG_SHAPE_SIZE, &fp->f_pos);

				memset(sign, 0, MAX_SIG_SHAPE_SIZE);
				memcpy(sign, temp, ptr->size);
				filp_close(fp, 0);

				if(memcmp(sign, ptr->data, ptr->size))
					ret += IS_INFECTED_SIG;
			}

			set_fs (oldfs);
			break;
		}

		ptr = ptr->next;
	}

	return ret;
}

void print_sig_state(int sig_flag)
{
	/* I used this function to test or debug */

	printk("[%s]", sig_flag & IS_HAVING_TARGET_EXT? "TARGET" : "NON_TARGET");
	printk("[%s]", sig_flag & IS_EMPTY_FILE? "EMPTY" : "NON_EMPTY");
	printk("[%s]", sig_flag & IS_TEMP_FILE? "TEMP" : "NON_TEMP");
	printk("[%s]", sig_flag & IS_INFECTED_EXT? "INFEXT" : "NON_INFEXT");
	printk("[%s]", sig_flag & IS_INFECTED_SIG? "INFSIG" : "NON_INFSIG");
}


//
