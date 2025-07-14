// import { Column, Entity, PrimaryGeneratedColumn } from 'typeorm';

// @Entity()
// export class User {
//   /**
//    * this decorator will help to auto generate id for the table.
//    */
//   @PrimaryGeneratedColumn()
//   id: number;

//   @Column({ type: 'varchar', length: 30 })
//   name: string;

//   @Column({ type: 'varchar', length: 15 })
//   username: string;

//   @Column({ type: 'varchar', length: 40 })
//   email: string;

//   @Column({ type: 'int' })
//   age: number;

//   @Column({ type: 'varchar' })
//   password: string;

//   @Column({ type: 'enum', enum: ['m', 'f', 'u'] })
//   /**
//    * m - male
//    * f - female
//    * u - unspecified
//    */
//   gender: string;
// }

import { Entity, PrimaryGeneratedColumn, Column, CreateDateColumn, UpdateDateColumn } from 'typeorm';

@Entity('users') 
export class Users {
  @PrimaryGeneratedColumn('uuid') 
  id: string;

  @Column({ unique: true }) 
  email: string;

  @Column()
  password: string;

  @Column('simple-array', { default: ['user'] }) // Stores roles as an array of strings
  roles: string[];

  @Column({ default: false }) // Boolean column, defaults to false
  twoFactorEnabled: boolean;

  @Column({ nullable: true }) // This column can be null in the database
  twoFactorSecret?: string; // Optional property in interface, nullable in DB

  @Column({ default: false })
  emailVerified: boolean;

  @Column({ nullable: true })
  emailVerificationToken?: string;

  @Column({ nullable: true })
  passwordResetToken?: string;

  @Column({ type: 'timestamp', nullable: true }) // Stores date and time, can be null
  passwordResetExpires?: Date;

  @Column({ default: 0 })
  loginAttempts: number;

  @Column({ type: 'timestamp', nullable: true })
  lockUntil?: Date;

  @CreateDateColumn() // Automatically sets the creation timestamp
  createdAt: Date;

  @UpdateDateColumn() // Automatically updates the timestamp on entity updates
  updatedAt: Date;
}